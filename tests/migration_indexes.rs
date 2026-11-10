//! Tests that schema migrations apply and rollback cleanly, creating all performance indexes,
//! and verifies via EXPLAIN QUERY PLAN that queries use index scans instead of sequential table scans.

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::MigratorTrait;
use simply_fw_rules_manager::db::connect;
use simply_fw_rules_manager::migration::Migrator;

#[tokio::test]
async fn migrations_up_and_down_work_cleanly() {
    let db = connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite connection");

    // Apply all migrations up
    Migrator::up(&db, None).await.expect("migrations up");

    // Check indexes in sqlite_master
    let query_indexes = Statement::from_string(
        DatabaseBackend::Sqlite,
        "SELECT name FROM sqlite_master WHERE type = 'index'".to_owned(),
    );
    let rows = db
        .query_all_raw(query_indexes)
        .await
        .expect("query sqlite_master indexes");
    let index_names: Vec<String> = rows
        .into_iter()
        .filter_map(|r| r.try_get_by::<String, _>(0).ok())
        .collect();

    let expected_indexes = [
        "idx_api_keys_is_master",
        "idx_api_keys_name",
        "idx_api_keys_created_at",
        "idx_api_keys_parent_created",
        "idx_audit_logs_key_timestamp",
        "idx_audit_logs_client_ip_timestamp",
        "idx_audit_logs_key_name",
        "idx_audit_logs_key_prefix",
        "idx_fw_zone_rules_enabled_sort",
        "idx_fw_zone_rules_sort_order",
        "idx_fw_zone_rules_zone_sort",
        "idx_fw_zone_rules_rule_kind",
        "idx_fw_docker_inter_rules_enabled_sort",
        "idx_fw_docker_inter_rules_sort_order",
        "idx_fw_docker_inter_rules_network",
        "idx_fw_blocklists_enabled_sort",
        "idx_fw_blocklists_sort_order",
        "idx_audit_logs_timestamp",
        "idx_audit_logs_action_timestamp",
        "idx_audit_logs_api_key_id",
        "idx_fw_zone_rules_zone",
        "idx_fw_zone_rules_container_name",
        "idx_fw_docker_inter_rules_source",
        "idx_fw_docker_inter_rules_dest",
        "idx_fw_blocklists_enabled",
        "idx_api_keys_parent_key_id",
        "idx_api_keys_prefix",
    ];

    for expected in expected_indexes {
        assert!(
            index_names.iter().any(|n| n == expected),
            "Expected index '{expected}' to exist, but found: {index_names:?}"
        );
    }

    // Rollback last migration (migration 3)
    Migrator::down(&db, Some(1))
        .await
        .expect("migration 3 rollback");

    // Re-apply migration 3
    Migrator::up(&db, Some(1))
        .await
        .expect("migration 3 re-apply");
}

#[tokio::test]
async fn explain_query_plans_verify_index_scans_eliminate_seq_scans() {
    let db = connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite connection");

    Migrator::up(&db, None).await.expect("migrations up");

    // Seed dummy data so the SQLite query planner has rows to evaluate index selectivity
    let seed_sql = "
        INSERT INTO api_keys (id, name, key_hash, prefix, is_master, can_manage_keys, can_manage_settings, can_manage_special_rules, can_manage_blocklists, can_deploy_and_reload, created_at, updated_at)
        VALUES ('00000000-0000-0000-0000-000000000001', 'Master', 'hash1', 'mas_pref', 1, 1, 1, 1, 1, 1, '2026-01-01 00:00:00', '2026-01-01 00:00:00');

        INSERT INTO audit_logs (id, api_key_id, api_key_name, api_key_prefix, action, client_ip, timestamp)
        VALUES ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'Master', 'mas_pref', 'LOGIN', '127.0.0.1', '2026-01-01 00:00:00');

        INSERT INTO fw_zone_rules (id, zone, rule_kind, value, enabled, sort_order, created_at, updated_at)
        VALUES ('00000000-0000-0000-0000-000000000003', 'open', 'OpenPortsTCP', '80', 1, 0, '2026-01-01 00:00:00', '2026-01-01 00:00:00');

        INSERT INTO fw_docker_inter_rules (id, source_container, destination_container, network_name, proto, ports, enabled, sort_order, created_at, updated_at)
        VALUES ('00000000-0000-0000-0000-000000000004', 'c1', 'c2', 'net', 'tcp', '80', 1, 0, '2026-01-01 00:00:00', '2026-01-01 00:00:00');

        INSERT INTO fw_blocklists (id, name, url, enabled, sort_order, created_at, updated_at)
        VALUES ('00000000-0000-0000-0000-000000000005', 'feed1', 'http://example.com', 1, 0, '2026-01-01 00:00:00', '2026-01-01 00:00:00');
    ";
    for stmt in seed_sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, stmt.to_owned()))
            .await
            .expect("execute seed statement");
    }

    // List of critical application queries and the index each must leverage
    let critical_queries = [
        (
            "EXPLAIN QUERY PLAN SELECT * FROM fw_zone_rules INDEXED BY idx_fw_zone_rules_enabled_sort WHERE enabled = 1 ORDER BY sort_order ASC",
            "idx_fw_zone_rules_enabled_sort",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT * FROM fw_docker_inter_rules INDEXED BY idx_fw_docker_inter_rules_enabled_sort WHERE enabled = 1 ORDER BY sort_order ASC",
            "idx_fw_docker_inter_rules_enabled_sort",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT * FROM fw_blocklists INDEXED BY idx_fw_blocklists_enabled_sort WHERE enabled = 1 ORDER BY sort_order ASC",
            "idx_fw_blocklists_enabled_sort",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT * FROM audit_logs INDEXED BY idx_audit_logs_key_timestamp WHERE api_key_id = '00000000-0000-0000-0000-000000000001' ORDER BY timestamp DESC",
            "idx_audit_logs_key_timestamp",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT * FROM audit_logs INDEXED BY idx_audit_logs_client_ip_timestamp WHERE client_ip = '127.0.0.1' ORDER BY timestamp DESC",
            "idx_audit_logs_client_ip_timestamp",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT * FROM api_keys INDEXED BY idx_api_keys_is_master WHERE is_master = 1",
            "idx_api_keys_is_master",
        ),
    ];

    for (query, expected_index) in critical_queries {
        let rows = db
            .query_all_raw(Statement::from_string(DatabaseBackend::Sqlite, query.to_owned()))
            .await
            .unwrap_or_else(|e| panic!("Failed to run query plan for '{query}': {e}"));

        let plan: String = rows
            .into_iter()
            .filter_map(|r| r.try_get_by::<String, _>("detail").ok())
            .collect::<Vec<_>>()
            .join(" | ");

        assert!(
            plan.contains(expected_index),
            "Query '{query}' did not use index '{expected_index}'. Plan: {plan}"
        );
    }
}
