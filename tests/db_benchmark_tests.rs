//! Systematic before vs. after performance benchmarks quantifying the impact of database optimizations:
//! 1. Batch insertion (`insert_many`) vs. Iterative single-row insertion (`insert`).
//! 2. Index Scan vs. Sequential Scan (`NOT INDEXED`) across core tables and query patterns.

use std::time::Instant;

use sea_orm::{
    ActiveModelTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait, Set,
    Statement,
};
use simply_fw_rules_manager::db::connect;
use simply_fw_rules_manager::entities::{api_key, audit_log, fw_docker_inter_rule, fw_zone_rule};
use simply_fw_rules_manager::migration::Migrator;
use time::OffsetDateTime;
use uuid::Uuid;

const BATCH_SIZE: usize = 300;
const DATASET_SIZE: usize = 5_000;
const QUERY_ITERATIONS: u32 = 100;

fn micros_to_f64(micros: u128) -> f64 {
    f64::from(u32::try_from(micros).unwrap_or(u32::MAX))
}

#[derive(Debug)]
pub struct BenchmarkResult {
    pub name: &'static str,
    pub before_micros: u128,
    pub after_micros: u128,
    pub speedup_ratio: f64,
}

impl BenchmarkResult {
    #[must_use]
    pub fn new(name: &'static str, before_micros: u128, after_micros: u128) -> Self {
        let before_f = micros_to_f64(before_micros);
        let after_f = micros_to_f64(after_micros);
        let speedup_ratio = if after_micros == 0 {
            before_f
        } else {
            before_f / after_f
        };
        Self {
            name,
            before_micros,
            after_micros,
            speedup_ratio,
        }
    }
}

async fn bench_batch_ingestion(db: &DatabaseConnection) -> BenchmarkResult {
    let now = OffsetDateTime::now_utc();
    let single_models: Vec<fw_zone_rule::ActiveModel> = (0..BATCH_SIZE)
        .map(|i| fw_zone_rule::ActiveModel {
            id: Set(Uuid::new_v4()),
            zone: Set("open".to_owned()),
            rule_kind: Set("OpenPortsTCP".to_owned()),
            value: Set(format!("{i}")),
            container_name: Set(None),
            enabled: Set(i % 2 == 0),
            comment: Set(Some("benchmark single insert".to_owned())),
            sort_order: Set(i32::try_from(i).unwrap_or(0)),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .collect();

    let start_single = Instant::now();
    for model in single_models {
        model.insert(db).await.expect("insert single row");
    }
    let before_insert_micros = start_single.elapsed().as_micros();

    fw_zone_rule::Entity::delete_many()
        .exec(db)
        .await
        .expect("clear table");

    let batch_models: Vec<fw_zone_rule::ActiveModel> = (0..BATCH_SIZE)
        .map(|i| fw_zone_rule::ActiveModel {
            id: Set(Uuid::new_v4()),
            zone: Set("open".to_owned()),
            rule_kind: Set("OpenPortsTCP".to_owned()),
            value: Set(format!("{i}")),
            container_name: Set(None),
            enabled: Set(i % 2 == 0),
            comment: Set(Some("benchmark batch insert".to_owned())),
            sort_order: Set(i32::try_from(i).unwrap_or(0)),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .collect();

    let start_batch = Instant::now();
    fw_zone_rule::Entity::insert_many(batch_models)
        .exec(db)
        .await
        .expect("batch insert_many");
    let after_insert_micros = start_batch.elapsed().as_micros();

    BenchmarkResult::new(
        "Zone Rules Ingestion (300 rows): Single-row insert vs. Batched insert_many",
        before_insert_micros,
        after_insert_micros,
    )
}

async fn seed_benchmark_api_keys(db: &DatabaseConnection, now: OffsetDateTime) -> Uuid {
    let target_key_id = Uuid::new_v4();
    let mut api_keys = Vec::with_capacity(100);
    for i in 0..100 {
        let is_master = i == 0;
        api_keys.push(api_key::ActiveModel {
            id: Set(if is_master {
                target_key_id
            } else {
                Uuid::new_v4()
            }),
            name: Set(format!("key-{i}")),
            key_hash: Set(format!("hash-{i:064x}")),
            signing_secret: Set(None),
            prefix: Set(format!("pref{i:04}")),
            is_master: Set(is_master),
            can_manage_keys: Set(api_key::ScopeAccess::Granted),
            can_manage_settings: Set(api_key::ScopeAccess::Granted),
            can_manage_special_rules: Set(api_key::ScopeAccess::Granted),
            can_manage_blocklists: Set(api_key::ScopeAccess::Granted),
            can_deploy_and_reload: Set(api_key::ScopeAccess::Granted),
            parent_key_id: Set(None),
            bound_ips: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        });
    }
    api_key::Entity::insert_many(api_keys)
        .exec(db)
        .await
        .expect("seed api_keys");
    target_key_id
}

async fn seed_benchmark_dataset(db: &DatabaseConnection) -> Uuid {
    let now = OffsetDateTime::now_utc();
    let target_key_id = seed_benchmark_api_keys(db, now).await;

    let mut zone_rules = Vec::with_capacity(DATASET_SIZE);
    let mut docker_rules = Vec::with_capacity(DATASET_SIZE);
    let mut audit_logs = Vec::with_capacity(DATASET_SIZE);

    for i in 0..DATASET_SIZE {
        zone_rules.push(fw_zone_rule::ActiveModel {
            id: Set(Uuid::new_v4()),
            zone: Set(if i % 3 == 0 {
                "open".to_owned()
            } else {
                "internal".to_owned()
            }),
            rule_kind: Set("OpenPortsTCP".to_owned()),
            value: Set(format!("{}", 1000 + i)),
            container_name: Set(if i % 2 == 0 {
                Some("traefik".to_owned())
            } else {
                None
            }),
            enabled: Set(i % 4 != 0),
            comment: Set(None),
            sort_order: Set(i32::try_from(i).unwrap_or(0)),
            created_at: Set(now),
            updated_at: Set(now),
        });
        docker_rules.push(fw_docker_inter_rule::ActiveModel {
            id: Set(Uuid::new_v4()),
            source_container: Set(format!("app-{}", i % 10)),
            destination_container: Set(format!("db-{}", i % 5)),
            network_name: Set("isolate".to_owned()),
            proto: Set("tcp".to_owned()),
            ports: Set("5432".to_owned()),
            enabled: Set(i % 3 != 0),
            comment: Set(None),
            sort_order: Set(i32::try_from(i).unwrap_or(0)),
            created_at: Set(now),
            updated_at: Set(now),
        });
        audit_logs.push(audit_log::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(if i % 2 == 0 {
                Some(target_key_id)
            } else {
                None
            }),
            api_key_name: Set(format!("key-{}", i % 20)),
            api_key_prefix: Set(format!("pref{:04}", i % 20)),
            action: Set(if i % 2 == 0 {
                "GENERATE_FILES".to_owned()
            } else {
                "RELOAD".to_owned()
            }),
            target_resource: Set(None),
            details: Set(None),
            client_ip: Set(if i % 5 == 0 {
                "192.168.1.50".to_owned()
            } else {
                "10.0.0.1".to_owned()
            }),
            timestamp: Set(now),
        });
    }

    for chunk in zone_rules.chunks(200) {
        fw_zone_rule::Entity::insert_many(chunk.to_vec())
            .exec(db)
            .await
            .expect("seed zone_rules");
    }
    for chunk in docker_rules.chunks(200) {
        fw_docker_inter_rule::Entity::insert_many(chunk.to_vec())
            .exec(db)
            .await
            .expect("seed docker_rules");
    }
    for chunk in audit_logs.chunks(200) {
        audit_log::Entity::insert_many(chunk.to_vec())
            .exec(db)
            .await
            .expect("seed audit_logs");
    }
    target_key_id
}

async fn bench_query_pair(
    db: &DatabaseConnection,
    name: &'static str,
    unindexed_sql: &str,
    indexed_sql: &str,
) -> BenchmarkResult {
    let q_unindexed = Statement::from_string(DatabaseBackend::Sqlite, unindexed_sql);
    let start = Instant::now();
    for _ in 0..QUERY_ITERATIONS {
        db.query_all_raw(q_unindexed.clone())
            .await
            .expect("query unindexed");
    }
    let before = start.elapsed().as_micros();

    let q_indexed = Statement::from_string(DatabaseBackend::Sqlite, indexed_sql);
    let start = Instant::now();
    for _ in 0..QUERY_ITERATIONS {
        db.query_all_raw(q_indexed.clone())
            .await
            .expect("query indexed");
    }
    let after = start.elapsed().as_micros();

    BenchmarkResult::new(name, before, after)
}

#[tokio::test]
async fn benchmark_db_optimizations_quantified() {
    let db = connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite connection");
    Migrator::up(&db, None).await.expect("migrations up");

    let mut results = vec![bench_batch_ingestion(&db).await];
    let target_key_id = seed_benchmark_dataset(&db).await;

    results.push(
        bench_query_pair(
            &db,
            "fw_zone_rules Generator Query (100 runs): Full Table Scan vs. idx_fw_zone_rules_enabled_sort",
            "SELECT * FROM fw_zone_rules NOT INDEXED WHERE enabled = 1 ORDER BY sort_order ASC",
            "SELECT * FROM fw_zone_rules INDEXED BY idx_fw_zone_rules_enabled_sort WHERE enabled = 1 ORDER BY sort_order ASC",
        )
        .await,
    );
    results.push(
        bench_query_pair(
            &db,
            "fw_docker_inter_rules Generator Query (100 runs): Full Table Scan vs. idx_fw_docker_inter_rules_enabled_sort",
            "SELECT * FROM fw_docker_inter_rules NOT INDEXED WHERE enabled = 1 ORDER BY sort_order ASC",
            "SELECT * FROM fw_docker_inter_rules INDEXED BY idx_fw_docker_inter_rules_enabled_sort WHERE enabled = 1 ORDER BY sort_order ASC",
        )
        .await,
    );
    results.push(
        bench_query_pair(
            &db,
            "audit_logs Non-Master Feed (100 runs): Full Table Scan vs. idx_audit_logs_key_timestamp",
            &format!("SELECT * FROM audit_logs NOT INDEXED WHERE api_key_id = '{target_key_id}' ORDER BY timestamp DESC LIMIT 50"),
            &format!("SELECT * FROM audit_logs INDEXED BY idx_audit_logs_key_timestamp WHERE api_key_id = '{target_key_id}' ORDER BY timestamp DESC LIMIT 50"),
        )
        .await,
    );
    results.push(
        bench_query_pair(
            &db,
            "api_keys Master Discovery (100 runs): Full Table Scan vs. idx_api_keys_is_master",
            "SELECT * FROM api_keys NOT INDEXED WHERE is_master = 1 LIMIT 1",
            "SELECT * FROM api_keys INDEXED BY idx_api_keys_is_master WHERE is_master = 1 LIMIT 1",
        )
        .await,
    );

    println!("\n==================== DATABASE OPTIMIZATION BENCHMARK REPORT ====================");
    println!(
        "{:<65} | {:>10} | {:>10} | {:>10}",
        "Optimization Target", "Before (ms)", "After (ms)", "Speedup"
    );
    println!("{:-<65}-|-{:-<10}-|-{:-<10}-|-{:-<10}", "", "", "", "");
    for r in &results {
        println!(
            "{:<65} | {:>10.3} | {:>10.3} | {:>9.2}x",
            r.name,
            micros_to_f64(r.before_micros) / 1_000.0,
            micros_to_f64(r.after_micros) / 1_000.0,
            r.speedup_ratio
        );
        assert!(
            r.after_micros <= r.before_micros * 2,
            "Optimization '{}' resulted in significant performance regression",
            r.name
        );
    }
    println!("================================================================================\n");
}
