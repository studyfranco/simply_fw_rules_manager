# File Map (`simply_fw_rules_manager`)

```text
simply_fw_rules_manager/
├── AGENT.MD                      # Architectural instructions & security invariants
├── AGENT_NOTES.MD                # Session engineering notes & architectural decisions
├── API_REFERENCE.md              # Complete REST API contract
├── Cargo.toml                    # Rust 2024 crate manifest
├── Dockerfile                    # Multi-stage container build
├── FILE_MAP.MD                   # Repository file structure
├── RBAC_MODEL.md                 # Authentication & authorization specification
├── README.md                     # User & deployment documentation
├── SCHEMA.MD                     # Database schema documentation
├── docker-compose.yml            # Container orchestration manifest
├── example/                      # Production reference configurations
│   ├── INDEX.md                  # Detailed index of MainServ, Serv1, Serv2 & Ansible playbooks
│   ├── MainServ/                 # MainServ /etc/firewall, Docker stacks & fail2ban configs
│   ├── Serv1/                    # Serv1 simply_firewall stack & production SQLite DBs
│   ├── Serv2/                    # Serv2 fail2ban & CrowdSec bouncer configs
│   └── serverInstallation/       # Ansible roles for server & firewall deployment
├── scripts_etc/                  # Refactored firewall engine scripts
│   ├── AUDIT_FIREWALL_SCRIPTS.md # Technical audit & impact analysis of firewall scripts
│   ├── firewall                  # Main netfilter/ipset orchestrator
│   ├── firewall.set.ip           # Atomic ipset loader (restore -!)
│   └── firewall.tools            # Immutable system constants & generic Docker/iptables helpers
├── src/
│   ├── main.rs                   # Tokio runtime entrypoint & graceful shutdown
│   ├── lib.rs                    # Axum router assembly & middleware stack
│   ├── config.rs                 # Environment configuration loader
│   ├── crypto.rs                 # XChaCha20-Poly1305 SecretCipher (enc:v1:...)
│   ├── db.rs                     # SeaORM connection pool & SQLite Immediate tx setup
│   ├── error.rs                  # Centralized ApiError -> HTTP status mapper
│   ├── extract.rs                # Rejecting JsonQuery/Path extractors
│   ├── master.rs                 # Master API key & initial /example import seeding
│   ├── middleware.rs             # CANONICAL_V1 HMAC-SHA256 + ReplayGuard + IP binding
│   ├── replay.rs                 # Bounded nonce cache within ±300s timestamp window
│   ├── state.rs                  # Shared AppState
│   ├── importer.rs               # Parser & refactorer for firewall.settings/.rules.special/.get.list
│   ├── docker.rs                 # Docker Engine client (Unix socket & HTTP/TCP)
│   ├── validator.rs              # 3-stage checker (bash -n, shellcheck, variable resolution)
│   ├── generator.rs              # Dynamic file generator & atomic disk writer
│   ├── hook_client.rs            # Signed CANONICAL_V1 client for simply_hook_executor
│   ├── api/
│   │   ├── mod.rs                # Route handlers re-export
│   │   ├── audit.rs              # GET /api/audit + AuditLog writer
│   │   ├── keys.rs               # CRUD /api/keys
│   │   ├── settings.rs           # CRUD /api/firewall/settings, /zones, /docker-rules
│   │   ├── docker.rs             # GET /api/docker/discovery
│   │   ├── special_rules.rs      # GET/PUT/POST /api/firewall/special-rules
│   │   ├── blocklists.rs         # CRUD + live URL tester /api/firewall/blocklists
│   │   └── deploy.rs             # Preview, Import, Generate, Reload & Update Containers
│   ├── entities/                 # SeaORM 2.0 entity models
│   └── migration/                # Two-phase SQL-agnostic migrations
├── static/
│   ├── index.html                # Single-Page Application shell (KDE Breeze Dark)
│   ├── style.css                 # Unified ecosystem stylesheet + code editor & status badges
│   └── app.js                    # Vanilla ES6 SPA client with WebCrypto HMAC signing
└── tests/
    ├── api_integration.rs        # End-to-end API, validator, generator & hook client tests
    └── source_hygiene.rs         # AST JS syntax, DOM ID, raw-SQL & unwrap/expect hygiene tests
```
