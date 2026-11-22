//! End-to-end integration tests for `simply_fw_rules_manager`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sea_orm::{ActiveModelTrait, Set};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
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

    let now = OffsetDateTime::now_utc();
    let master_row = api_key::ActiveModel {
        id: Set(master_id),
        name: Set("Master Key".to_owned()),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(sealed_secret)),
        prefix: Set("test-mas".to_owned()),
        is_master: Set(true),
        can_manage_keys: Set(api_key::ScopeAccess::Granted),
        can_manage_settings: Set(api_key::ScopeAccess::Granted),
        can_manage_special_rules: Set(api_key::ScopeAccess::Granted),
        can_manage_blocklists: Set(api_key::ScopeAccess::Granted),
        can_deploy_and_reload: Set(api_key::ScopeAccess::Granted),
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

fn signed_request_with_ts(
    method_str: &str,
    uri: &str,
    api_key: &str,
    signing_secret: &str,
    body_opt: Option<&Value>,
    timestamp: &str,
) -> Request<Body> {
    let body_bytes = body_opt.map_or_else(Vec::new, |v| serde_json::to_vec(v).expect("json bytes"));
    let sig = compute_signature(signing_secret, method_str, uri, timestamp, &body_bytes)
        .expect("compute signature");

    let mut builder = Request::builder()
        .method(method_str)
        .uri(uri)
        .header("X-API-Key", api_key)
        .header("X-Timestamp", timestamp)
        .header("X-Signature-256", sig)
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))));

    if body_opt.is_some() {
        builder = builder.header("Content-Type", "application/json");
    }

    builder.body(Body::from(body_bytes)).expect("build request")
}

fn signed_request(
    method_str: &str,
    uri: &str,
    api_key: &str,
    signing_secret: &str,
    body_opt: Option<&Value>,
) -> Request<Body> {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp().to_string();
    signed_request_with_ts(
        method_str,
        uri,
        api_key,
        signing_secret,
        body_opt,
        &timestamp,
    )
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
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
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
    assert_ne!(
        data["tools_functions"].as_array().unwrap().as_slice(),
        [] as [serde_json::Value; 0],
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

async fn seed_and_test_blocklist_generation(
    app: &axum::Router,
    mock_server: &MockServer,
    tmp_dir: &tempfile::TempDir,
) {
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
    let (st, settings_res) = response_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(settings_res["has_hook_api_key"], true);
    assert_eq!(settings_res["has_hook_signing_secret"], true);
    assert!(
        settings_res.get("hook_executor_api_key").is_none(),
        "plaintext hook_executor_api_key must never be returned in API responses"
    );
}

#[tokio::test]
async fn blocklist_live_test_and_atomic_generate_and_hook_reload_work() {
    let (app, _state) = setup_test_env().await;
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/feed/v1/abuseipdb/list.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("# Exported feed\n198.51.100.0/24\n203.0.113.42\n2001:db8::/32\n"),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/hooks/firewall-reload/execute"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "SUCCESS",
            "exit_code": 0,
            "stdout": "Firewall reloaded"
        })))
        .mount(&mock_server)
        .await;

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    seed_and_test_blocklist_generation(&app, &mock_server, &tmp_dir).await;

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

    let get_list_on_disk =
        std::fs::read_to_string(tmp_dir.path().join("firewall.get.list")).unwrap();
    assert!(get_list_on_disk.contains("abuseipdb_exporter"));
    assert!(!get_list_on_disk.contains("api.abuseipdb.com"));

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

async fn create_bound_operator_key(app: &axum::Router) -> (String, String) {
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
    (
        body["raw_key"].as_str().unwrap().to_owned(),
        body["signing_secret"].as_str().unwrap().to_owned(),
    )
}

async fn assert_sig_prefix_and_replay_guards(
    app: &axum::Router,
    allowed_addr: std::net::SocketAddr,
) {
    use axum::extract::ConnectInfo;

    let mut req_prefix = signed_request(
        "GET",
        "/api/settings",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
    );
    req_prefix
        .extensions_mut()
        .insert(ConnectInfo(allowed_addr));
    let current_sig = req_prefix
        .headers()
        .get("X-Signature-256")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let bare_hex = current_sig.strip_prefix("sha256=").unwrap();
    req_prefix
        .headers_mut()
        .insert("X-Signature-256", bare_hex.parse().unwrap());
    let (st_prefix, _) = response_json(app.clone().oneshot(req_prefix).await.unwrap()).await;
    assert_eq!(st_prefix, StatusCode::UNAUTHORIZED);

    let replay_ts = OffsetDateTime::now_utc().unix_timestamp().to_string();
    let mut req1 = signed_request_with_ts(
        "GET",
        "/api/settings?replay_test=1",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
        &replay_ts,
    );
    req1.extensions_mut().insert(ConnectInfo(allowed_addr));
    let (st1, _) = response_json(app.clone().oneshot(req1).await.unwrap()).await;
    assert_eq!(st1, StatusCode::OK);

    let mut req2 = signed_request_with_ts(
        "GET",
        "/api/settings?replay_test=1",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
        &replay_ts,
    );
    req2.extensions_mut().insert(ConnectInfo(allowed_addr));
    let (st2, err2) = response_json(app.clone().oneshot(req2).await.unwrap()).await;
    assert_eq!(st2, StatusCode::UNAUTHORIZED);
    assert!(
        err2["error"]
            .as_str()
            .unwrap()
            .contains("already been used")
    );
}

#[tokio::test]
async fn key_bound_ips_enforcement_and_daughter_key_rbac() {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    let (app, _state) = setup_test_env().await;
    let (op_key, op_secret) = create_bound_operator_key(&app).await;

    let mut req_allowed = signed_request(
        "GET",
        "/api/firewall/blocklists?probe=allowed",
        &op_key,
        &op_secret,
        None,
    );
    let allowed_addr: SocketAddr = "192.168.1.50:54321".parse().unwrap();
    req_allowed
        .extensions_mut()
        .insert(ConnectInfo(allowed_addr));
    let (st_allowed, _) = response_json(app.clone().oneshot(req_allowed).await.unwrap()).await;
    assert_eq!(st_allowed, StatusCode::OK);

    let mut req_forbidden = signed_request(
        "GET",
        "/api/firewall/blocklists?probe=forbidden",
        &op_key,
        &op_secret,
        None,
    );
    let forbidden_addr: SocketAddr = "172.16.0.1:54321".parse().unwrap();
    req_forbidden
        .extensions_mut()
        .insert(ConnectInfo(forbidden_addr));
    let (st_forbidden, err_body) =
        response_json(app.clone().oneshot(req_forbidden).await.unwrap()).await;
    assert_eq!(st_forbidden, StatusCode::FORBIDDEN);
    assert_eq!(err_body["error"], "Client IP not allowed");

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
    assert!(
        err_rbac["error"]
            .as_str()
            .unwrap()
            .contains("Missing can_manage_keys")
    );

    let mut req_audit_op = signed_request("GET", "/api/audit-logs", &op_key, &op_secret, None);
    req_audit_op
        .extensions_mut()
        .insert(ConnectInfo(allowed_addr));
    let (st_audit_op, err_audit) =
        response_json(app.clone().oneshot(req_audit_op).await.unwrap()).await;
    assert_eq!(st_audit_op, StatusCode::FORBIDDEN);
    assert_eq!(err_audit["error"], "Only master keys can view audit logs");

    let mut req_audit_master = signed_request(
        "GET",
        "/api/audit-logs",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
    );
    req_audit_master
        .extensions_mut()
        .insert(ConnectInfo(allowed_addr));
    let (st_audit_master, _) =
        response_json(app.clone().oneshot(req_audit_master).await.unwrap()).await;
    assert_eq!(st_audit_master, StatusCode::OK);

    assert_sig_prefix_and_replay_guards(&app, allowed_addr).await;
}

async fn assert_injection_and_ssrf_rejected(
    app: &axum::Router,
    state: &simply_fw_rules_manager::state::AppState,
) {
    let cases = [
        (
            "PUT",
            "/api/firewall/settings",
            json!({ "main_inter": "out\"; touch /tmp/pwn #" }),
        ),
        (
            "PUT",
            "/api/firewall/settings",
            json!({ "country_open_port": "FR;id" }),
        ),
        (
            "POST",
            "/api/firewall/zones",
            json!({
                "zone": "ww",
                "rule_kind": "DockerTCP",
                "value": "443,ext,traefik$(id),443"
            }),
        ),
        (
            "POST",
            "/api/firewall/docker-rules",
            json!({
                "source_container": "traefik",
                "destination_container": "app",
                "network_name": "ext",
                "proto": "tcp",
                "ports": "80;id"
            }),
        ),
        (
            "POST",
            "/api/firewall/blocklists",
            json!({
                "name": "evil_bl",
                "url": "https://example.org/$(whoami).txt"
            }),
        ),
    ];
    for (method_str, uri, body) in cases {
        let (st, _) = response_json(
            app.clone()
                .oneshot(signed_request(
                    method_str,
                    uri,
                    TEST_MASTER_KEY,
                    TEST_MASTER_SECRET,
                    Some(&body),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "expected 400 on {uri}");
    }

    let traversal_import = json!({ "source_dir": "../../etc" });
    let (st, _) = response_json(
        app.clone()
            .oneshot(signed_request(
                "POST",
                "/api/firewall/import",
                TEST_MASTER_KEY,
                TEST_MASTER_SECRET,
                Some(&traversal_import),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert!(st == StatusCode::BAD_REQUEST || st == StatusCode::FORBIDDEN);

    let mut prod_like_state = state.clone();
    prod_like_state.allow_private_urls = false;
    let prod_app = create_app(prod_like_state);
    let ssrf_bl = json!({
        "name": "imds_probe",
        "url": "http://169.254.169.254/latest/meta-data/"
    });
    let (st, _) = response_json(
        prod_app
            .oneshot(signed_request(
                "POST",
                "/api/firewall/blocklists",
                TEST_MASTER_KEY,
                TEST_MASTER_SECRET,
                Some(&ssrf_bl),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

async fn assert_scoped_gets_and_r4_rbac(app: &axum::Router) {
    let op_create = json!({
        "name": "BL Only",
        "can_manage_blocklists": true
    });
    let (st, op_body) = response_json(
        app.clone()
            .oneshot(signed_request(
                "POST",
                "/api/keys",
                TEST_MASTER_KEY,
                TEST_MASTER_SECRET,
                Some(&op_create),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let op_key = op_body["raw_key"].as_str().unwrap();
    let op_sec = op_body["signing_secret"].as_str().unwrap();

    for forbidden_get in [
        "/api/firewall/settings",
        "/api/firewall/zones",
        "/api/firewall/docker-rules",
        "/api/firewall/special-rules",
        "/api/firewall/tools-functions",
        "/api/firewall/preview",
        "/api/docker/discovery",
    ] {
        let (st, _) = response_json(
            app.clone()
                .oneshot(signed_request("GET", forbidden_get, op_key, op_sec, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "expected 403 on {forbidden_get}");
    }

    let parent_create = json!({
        "name": "Ops Parent",
        "can_manage_keys": true,
        "can_manage_blocklists": true,
        "can_manage_settings": true
    });
    let (st, parent_body) = response_json(
        app.clone()
            .oneshot(signed_request(
                "POST",
                "/api/keys",
                TEST_MASTER_KEY,
                TEST_MASTER_SECRET,
                Some(&parent_create),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let p_key = parent_body["raw_key"].as_str().unwrap();
    let p_sec = parent_body["signing_secret"].as_str().unwrap();

    for escalated in [
        json!({ "name": "Esc1", "can_manage_keys": true }),
        json!({ "name": "Esc2", "can_manage_settings": true }),
        json!({ "name": "Esc3", "can_manage_special_rules": true }),
    ] {
        let (st, _) = response_json(
            app.clone()
                .oneshot(signed_request(
                    "POST",
                    "/api/keys",
                    p_key,
                    p_sec,
                    Some(&escalated),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    let ok_daughter = json!({ "name": "Safe Daughter", "can_manage_blocklists": true });
    let (st, _) = response_json(
        app.clone()
            .oneshot(signed_request(
                "POST",
                "/api/keys",
                p_key,
                p_sec,
                Some(&ok_daughter),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
}

#[tokio::test]
async fn security_hardening_bash_injection_ssrf_traversal_and_r4_rbac() {
    use axum::extract::ConnectInfo;
    use sea_orm::EntityTrait;
    use simply_fw_rules_manager::entities::fw_settings;
    use std::net::SocketAddr;

    let (app, state) = setup_test_env().await;

    assert_injection_and_ssrf_rejected(&app, &state).await;
    assert_scoped_gets_and_r4_rbac(&app).await;

    let save_key = json!({ "hook_executor_api_key": "super-secret-api-key" });
    let (st, resp_cfg) = response_json(
        app.clone()
            .oneshot(signed_request(
                "PUT",
                "/api/firewall/settings",
                TEST_MASTER_KEY,
                TEST_MASTER_SECRET,
                Some(&save_key),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(resp_cfg["has_hook_api_key"], true);
    assert!(resp_cfg.get("hook_executor_api_key").is_none());

    let db_row = fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await
        .unwrap()
        .unwrap();
    let stored = db_row.hook_executor_api_key.unwrap();
    assert!(
        simply_fw_rules_manager::crypto::SecretCipher::is_envelope(&stored),
        "hook_executor_api_key must be stored sealed in envelope"
    );

    let empty_save = json!({ "hook_executor_api_key": "" });
    let (st, resp_cfg2) = response_json(
        app.clone()
            .oneshot(signed_request(
                "PUT",
                "/api/firewall/settings",
                TEST_MASTER_KEY,
                TEST_MASTER_SECRET,
                Some(&empty_save),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(resp_cfg2["has_hook_api_key"], true);

    let ts = OffsetDateTime::now_utc().unix_timestamp().to_string();
    let sig = compute_signature(TEST_MASTER_SECRET, "GET", "/api/settings", &ts, b"").unwrap();
    let no_ci_req = Request::builder()
        .method("GET")
        .uri("/api/settings")
        .header("X-API-Key", TEST_MASTER_KEY)
        .header("X-Timestamp", ts)
        .header("X-Signature-256", sig)
        .body(Body::empty())
        .unwrap();
    assert!(
        no_ci_req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_none()
    );
    let (st, _) = response_json(app.oneshot(no_ci_req).await.unwrap()).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn audit_bounds_and_sorting_accept_legacy_sqlite_timestamps() {
    use sea_orm::ConnectionTrait;
    use sea_orm::sea_query::{Expr, Query};
    use simply_fw_rules_manager::entities::audit_log::{Column, Entity};

    let (app, state) = setup_test_env().await;
    for (action, timestamp) in [
        ("whole", "2026-01-01T00:00:10Z"),
        ("legacy", "2026-01-01T00:00:10.120+00:00"),
        ("current", "2026-01-01T00:00:10.12Z"),
        ("next", "2026-01-01T00:00:10.123Z"),
    ] {
        state
            .db
            .execute(
                Query::insert()
                    .into_table(Entity)
                    .columns([
                        Column::Id,
                        Column::ApiKeyName,
                        Column::ApiKeyPrefix,
                        Column::Action,
                        Column::ClientIp,
                        Column::Timestamp,
                    ])
                    .values_panic([
                        Expr::val(Uuid::new_v4()),
                        Expr::val("Test Key"),
                        Expr::val("test-key"),
                        Expr::val(action),
                        Expr::val("192.0.2.10"),
                        Expr::val(timestamp),
                    ]),
            )
            .await
            .expect("seed audit row");
    }

    let request = signed_request(
        "GET",
        "/api/audit-logs?since=2026-01-01T00:00:10Z&until=2026-01-01T00:00:10.12Z",
        TEST_MASTER_KEY,
        TEST_MASTER_SECRET,
        None,
    );
    let (status, response) = response_json(app.oneshot(request).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let entries = response.as_array().expect("audit entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[2]["action"], "whole");
    let actions: std::collections::BTreeSet<_> = entries[..2]
        .iter()
        .map(|entry| {
            assert_eq!(entry["timestamp"], "2026-01-01T00:00:10.12Z");
            entry["action"].as_str().expect("action")
        })
        .collect();
    assert_eq!(
        actions,
        std::collections::BTreeSet::from(["current", "legacy"])
    );
}
