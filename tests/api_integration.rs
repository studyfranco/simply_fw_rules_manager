//! End-to-end integration tests for `simply_fw_rules_manager`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, Set};
use sea_orm_migration::MigratorTrait;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use simply_fw_rules_manager::create_app;
use simply_fw_rules_manager::crypto::{SecretCipher, compute_signature};
use simply_fw_rules_manager::db::connect;
use simply_fw_rules_manager::docker::{
    ContainerNetworkAttachment, DiscoveredContainer, DiscoveredNetwork, DockerDiscoverySnapshot,
};
use simply_fw_rules_manager::entities::api_key;
use simply_fw_rules_manager::generator::build_files_bundle;
use simply_fw_rules_manager::importer::seed_if_empty;
use simply_fw_rules_manager::migration::Migrator;
use simply_fw_rules_manager::state::AppState;

const TEST_MASTER_KEY: &str = "test-master-api-key-1234567890";
const TEST_MASTER_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

async fn setup_test_env() -> (axum::Router, AppState) {
    let db = connect("sqlite::memory:").await.expect("in-memory sqlite");
    Migrator::up(&db, None).await.expect("migrations up");

    let master_id = Uuid::new_v4();
    let cipher = SecretCipher::Plaintext;
    let mut hasher = Sha256::new();
    hasher.update(TEST_MASTER_KEY.as_bytes());
    let key_hash = hex::encode(hasher.finalize());
    let sealed_secret = cipher.seal(TEST_MASTER_SECRET).expect("seal secret");

    let now = Utc::now();
    let master_row = api_key::ActiveModel {
        id: Set(master_id),
        name: Set("Master Key".to_owned()),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(sealed_secret)),
        prefix: Set("test-mas".to_owned()),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_settings: Set(true),
        can_manage_special_rules: Set(true),
        can_manage_blocklists: Set(true),
        can_deploy_and_reload: Set(true),
        parent_key_id: Set(None),
        bound_ips: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    master_row.insert(&db).await.expect("insert master key");

    seed_if_empty(&db)
        .await
        .expect("seed example firewall files");

    let state = AppState::for_tests(db, master_id).expect("build test state");
    let app = create_app(state.clone());
    (app, state)
}

fn signed_request(
    method_str: &str,
    uri: &str,
    api_key: &str,
    signing_secret: &str,
    body_opt: Option<&Value>,
) -> Request<Body> {
    let body_bytes = body_opt.map_or_else(Vec::new, |v| serde_json::to_vec(v).expect("json bytes"));
    let timestamp = Utc::now().timestamp().to_string();
    let sig = compute_signature(signing_secret, method_str, uri, &timestamp, &body_bytes)
        .expect("compute signature");

    let mut builder = Request::builder()
        .method(method_str)
        .uri(uri)
        .header("X-API-Key", api_key)
        .header("X-Timestamp", timestamp)
        .header("X-Signature-256", sig);

    if body_opt.is_some() {
        builder = builder.header("Content-Type", "application/json");
    }

    builder.body(Body::from(body_bytes)).expect("build request")
}

async fn response_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
        .await
        .expect("read body");
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

#[tokio::test]
async fn health_and_example_bootstrap_and_canonical_auth_work() {
    let (app, _state) = setup_test_env().await;

    // 1. Health & readiness
    let (st, body) = response_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    let (st, body) = response_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["status"], "ready");

    // 2. Unauthenticated /api/firewall/settings is rejected with 401
    let (st, _) = response_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/api/firewall/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // 3. Authenticated GET /api/firewall/settings returns imported MainServ settings
    let req = signed_request(
        "GET",
        "/api/firewall/settings",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
    );
    let (st, settings) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(settings["main_inter"], "out");
    assert_eq!(settings["country_open_port"], "FR,CH");
    assert!(
        settings["docker_network_with_internet_access"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "ext")
    );
}

#[tokio::test]
async fn dynamic_docker_filtering_omits_stopped_containers_on_generation() {
    let (_app, state) = setup_test_env().await;

    // Build a mock Docker discovery snapshot where 'traefik' and 'jellyfin_theatre' are running,
    // but 'prowlarr' and 'plexmediaserver' are stopped.
    let mut containers = Vec::new();
    for (name, st) in [
        ("traefik", "running"),
        ("jellyfin_theatre", "running"),
        ("prowlarr", "exited"),
        ("plexmediaserver", "exited"),
        ("pihole", "running"),
    ] {
        let mut nets = std::collections::BTreeMap::new();
        nets.insert(
            "ext".to_owned(),
            ContainerNetworkAttachment {
                ipv4: "172.18.0.10".to_owned(),
                ipv6: String::new(),
            },
        );
        containers.push(DiscoveredContainer {
            name: name.to_owned(),
            state: st.to_owned(),
            status: st.to_owned(),
            image: "test:latest".to_owned(),
            networks: nets,
        });
    }

    let snapshot = DockerDiscoverySnapshot {
        endpoint: "unix:///var/run/docker.sock".to_owned(),
        reachable: true,
        error: None,
        containers,
        networks: vec![DiscoveredNetwork {
            name: "ext".to_owned(),
            driver: "bridge".to_owned(),
            subnets: vec!["172.18.0.0/16".to_owned()],
        }],
    };

    let bundle = build_files_bundle(&state.db, &snapshot)
        .await
        .expect("build bundle");

    assert!(bundle.docker_filter_active);
    // traefik -> jellyfin_theatre must be included (both running)
    assert!(
        bundle
            .firewall_settings
            .contains("traefik;jellyfin_theatre;isolate;tcp;8096"),
        "running container pair must be written into firewall.settings"
    );
    // traefik -> prowlarr must be omitted because prowlarr is exited!
    assert!(
        !bundle
            .firewall_settings
            .contains("traefik;prowlarr;ext;tcp;9696"),
        "stopped destination container must be omitted from firewall.settings"
    );
    // plexmediaserver in openDockerTCP must be omitted because plexmediaserver is exited!
    assert!(
        !bundle.firewall_settings.contains("plexmediaserver"),
        "stopped container in openDockerTCP must be omitted from firewall.settings"
    );
    // traefik in WWopenDockerTCP must be present because traefik is running!
    assert!(
        bundle.firewall_settings.contains("443,ext,traefik,443"),
        "running container in WWopenDockerTCP must be present"
    );
    assert!(bundle.skipped_docker_inter_rules > 0);
    assert!(bundle.skipped_zone_rules > 0);
}

#[tokio::test]
async fn special_rules_validator_and_refactored_helpers_work() {
    let (app, _state) = setup_test_env().await;

    // 1. GET /api/firewall/special-rules returns refactored script using get_container_ipv4_on_network
    let req = signed_request(
        "GET",
        "/api/firewall/special-rules",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
    );
    let (st, data) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    let script = data["script_content"].as_str().unwrap();
    assert!(
        script.contains("get_container_ipv4_on_network"),
        "imported special rules must use generic Docker helper functions"
    );
    assert!(
        !data["tools_functions"].as_array().unwrap().is_empty(),
        "firewall.tools helper functions must be parsed and returned"
    );

    // 2. Saving a script with an undefined $CHAIN_FAKE variable is rejected with 422
    let bad_payload = json!({
        "script_content": "#!/bin/bash\ninsert_rules_with_test_ok_ipv4 \"-I $CHAIN_NON_EXISTENT 1 -j ACCEPT\"\n",
        "allow_warnings": true
    });
    let req = signed_request(
        "PUT",
        "/api/firewall/special-rules",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        Some(&bad_payload),
    );
    let (st, err_body) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        err_body["validation"]["undefined_variables"][0]["variable"],
        "CHAIN_NON_EXISTENT"
    );

    // 3. Saving a valid script referencing known system constants ($CHAINMAINOUTINTERWW, $IPSLISTGOODIP) succeeds
    let good_payload = json!({
        "script_content": "#!/bin/bash\nsource /etc/firewall/firewall.tools\ninsert_rules_with_test_ok_ipv4 \"-I $CHAINMAINOUTINTERWW 1 -m set --match-set $IPSLISTGOODIP src -j ACCEPT\"\n",
        "allow_warnings": true
    });
    let req = signed_request(
        "PUT",
        "/api/firewall/special-rules",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        Some(&good_payload),
    );
    let (st, ok_body) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(ok_body["validation"]["bash_n_ok"], true);
    assert_eq!(ok_body["validation"]["variables_ok"], true);
}

#[tokio::test]
async fn blocklist_live_test_and_atomic_generate_and_hook_reload_work() {
    let (app, _state) = setup_test_env().await;
    let mock_server = MockServer::start().await;

    // Mock a plaintext IPv4/IPv6/CIDR feed (e.g. from simply_ip_exporter)
    Mock::given(method("GET"))
        .and(path("/feed/v1/abuseipdb/list.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("# Exported feed\n198.51.100.0/24\n203.0.113.42\n2001:db8::/32\n"),
        )
        .mount(&mock_server)
        .await;

    // Mock simply_hook_executor endpoint
    Mock::given(method("POST"))
        .and(path("/api/hooks/firewall-reload/execute"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "SUCCESS",
            "exit_code": 0,
            "stdout": "Firewall reloaded"
        })))
        .mount(&mock_server)
        .await;

    // 1. Add the exporter blocklist feed
    let create_bl = json!({
        "name": "abuseipdb_exporter",
        "url": format!("{}/feed/v1/abuseipdb/list.txt", mock_server.uri()),
        "enabled": true,
        "description": "AbuseIPDB via simply_ip_exporter"
    });
    let req = signed_request(
        "POST",
        "/api/firewall/blocklists",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        Some(&create_bl),
    );
    let (st, bl_created) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::CREATED);
    let bl_id = bl_created["id"].as_str().unwrap();

    // 2. Test the blocklist URL
    let req = signed_request(
        "POST",
        &format!("/api/firewall/blocklists/{bl_id}/test"),
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
    );
    let (st, test_res) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(test_res["valid"], true);
    assert_eq!(test_res["valid_ipv4_count"], 2);
    assert_eq!(test_res["valid_ipv6_count"], 1);

    // 3. Configure output_dir to a temp directory and hook_executor_url to mock_server
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let update_cfg = json!({
        "output_dir": tmp_dir.path().to_str().unwrap(),
        "hook_executor_url": mock_server.uri(),
        "hook_executor_api_key": "hook-key-123",
        "hook_executor_signing_secret": "hook-secret-456",
        "hook_reload_name": "firewall-reload"
    });
    let req = signed_request(
        "PUT",
        "/api/firewall/settings",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        Some(&update_cfg),
    );
    let (st, _) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);

    // 4. Trigger Generate & Reload
    let req = signed_request(
        "POST",
        "/api/firewall/generate-and-reload",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
    );
    let (st, gen_res) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(gen_res["files_written"].as_array().unwrap().len(), 3);
    assert_eq!(gen_res["hook_result"]["status_code"], 200);

    // Verify the 3 files exist on disk and firewall.get.list has no AbuseIPDB curl/jq logic
    let get_list_on_disk =
        std::fs::read_to_string(tmp_dir.path().join("firewall.get.list")).unwrap();
    assert!(get_list_on_disk.contains("abuseipdb_exporter"));
    assert!(!get_list_on_disk.contains("api.abuseipdb.com"));

    // 5. Verify Audit Logs recorded the actions
    let req = signed_request(
        "GET",
        "/api/audit-logs",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
    );
    let (st, logs) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    let actions: Vec<&str> = logs
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|l| l["action"].as_str())
        .collect();
    assert!(actions.contains(&"CREATE_BLOCKLIST"));
    assert!(actions.contains(&"TEST_BLOCKLIST"));
    assert!(actions.contains(&"GENERATE_AND_RELOAD"));
}

#[tokio::test]
async fn key_bound_ips_enforcement_and_daughter_key_rbac() {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    let (app, _state) = setup_test_env().await;

    // 1. Master creates daughter key with bound_ips and blocklist management scope only
    let create_payload = json!({
        "name": "Operator Key",
        "can_manage_keys": false,
        "can_manage_settings": false,
        "can_manage_special_rules": false,
        "can_manage_blocklists": true,
        "can_deploy_and_reload": false,
        "bound_ips": "192.168.1.0/24, 10.0.0.1"
    });
    let req = signed_request(
        "POST",
        "/api/keys",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        Some(&create_payload),
    );
    let (st, body) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::CREATED);
    let op_key = body["raw_key"].as_str().unwrap().to_owned();
    let op_secret = body["signing_secret"].as_str().unwrap().to_owned();

    // 2. Request from permitted IP subnet (192.168.1.50) -> should succeed
    let mut req_allowed = signed_request(
        "GET",
        "/api/firewall/blocklists?probe=allowed",
        &op_key,
        &op_secret,
        None,
    );
    let allowed_addr: SocketAddr = "192.168.1.50:54321".parse().unwrap();
    req_allowed.extensions_mut().insert(ConnectInfo(allowed_addr));
    let (st_allowed, _) = response_json(app.clone().oneshot(req_allowed).await.unwrap()).await;
    assert_eq!(st_allowed, StatusCode::OK);

    // 3. Request from forbidden IP (172.16.0.1) -> should return 403 Forbidden
    let mut req_forbidden = signed_request(
        "GET",
        "/api/firewall/blocklists?probe=forbidden",
        &op_key,
        &op_secret,
        None,
    );
    let forbidden_addr: SocketAddr = "172.16.0.1:54321".parse().unwrap();
    req_forbidden.extensions_mut().insert(ConnectInfo(forbidden_addr));
    let (st_forbidden, err_body) = response_json(app.clone().oneshot(req_forbidden).await.unwrap()).await;
    assert_eq!(st_forbidden, StatusCode::FORBIDDEN);
    assert_eq!(err_body["error"], "Client IP not allowed");

    // 4. Operator tries to create another key without can_manage_keys -> 403 Forbidden
    let forbidden_create = json!({
        "name": "Sub key",
        "can_manage_keys": false
    });
    let mut req_rbac = signed_request(
        "POST",
        "/api/keys",
        &op_key,
        &op_secret,
        Some(&forbidden_create),
    );
    req_rbac.extensions_mut().insert(ConnectInfo(allowed_addr));
    let (st_rbac, err_rbac) = response_json(app.clone().oneshot(req_rbac).await.unwrap()).await;
    assert_eq!(st_rbac, StatusCode::FORBIDDEN);
    assert!(err_rbac["error"].as_str().unwrap().contains("Missing can_manage_keys"));

    // 5. Operator tries to view audit logs -> strictly forbidden (Master-only)
    let mut req_audit_op = signed_request("GET", "/api/audit-logs", &op_key, &op_secret, None);
    req_audit_op.extensions_mut().insert(ConnectInfo(allowed_addr));
    let (st_audit_op, err_audit) = response_json(app.clone().oneshot(req_audit_op).await.unwrap()).await;
    assert_eq!(st_audit_op, StatusCode::FORBIDDEN);
    assert_eq!(err_audit["error"], "Only master keys can view audit logs");

    // 6. Master tries to view audit logs -> 200 OK
    let mut req_audit_master = signed_request("GET", "/api/audit-logs", TEST_MASTER_KEY, TEST_MASTER_SECRET, None);
    req_audit_master.extensions_mut().insert(ConnectInfo(allowed_addr));
    let (st_audit_master, _) = response_json(app.clone().oneshot(req_audit_master).await.unwrap()).await;
    assert_eq!(st_audit_master, StatusCode::OK);

    // 7. Signature prefix enforcement: stripping "sha256=" prefix fails authentication
    let mut req_prefix = signed_request("GET", "/api/settings", TEST_MASTER_KEY, TEST_MASTER_SECRET, None);
    req_prefix.extensions_mut().insert(ConnectInfo(allowed_addr));
    let current_sig = req_prefix.headers().get("X-Signature-256").unwrap().to_str().unwrap().to_owned();
    let bare_hex = current_sig.strip_prefix("sha256=").unwrap();
    req_prefix.headers_mut().insert("X-Signature-256", bare_hex.parse().unwrap());
    let (st_prefix, _) = response_json(app.clone().oneshot(req_prefix).await.unwrap()).await;
    assert_eq!(st_prefix, StatusCode::UNAUTHORIZED);

    // 8. Anti-replay guard rejects duplicated request
    let mut req1 = signed_request("GET", "/api/settings?replay_test=1", TEST_MASTER_KEY, TEST_MASTER_SECRET, None);
    req1.extensions_mut().insert(ConnectInfo(allowed_addr));
    let (st1, _) = response_json(app.clone().oneshot(req1).await.unwrap()).await;
    assert_eq!(st1, StatusCode::OK);

    let mut req2 = signed_request("GET", "/api/settings?replay_test=1", TEST_MASTER_KEY, TEST_MASTER_SECRET, None);
    req2.extensions_mut().insert(ConnectInfo(allowed_addr));
    // Must fail because signature has already been recorded
    let (st2, err2) = response_json(app.clone().oneshot(req2).await.unwrap()).await;
    assert_eq!(st2, StatusCode::UNAUTHORIZED);
    assert!(err2["error"].as_str().unwrap().contains("already been used"));
}
