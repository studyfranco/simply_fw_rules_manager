//! Master API key identity pinning and bootstrap seeding.

use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::sync::OnceLock;

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::{SecretCipher, generate_signing_secret};
use crate::entities::api_key;
use crate::entities::prelude::ApiKey;

const MASTER_MARKER_INDEX: &str = "idx_api_keys_master_marker";
const API_KEYS_TABLE: &str = "api_keys";
const BANNER_WIDTH: usize = 82;

fn validate_hex_64(env_name: &str, raw: &str) -> Result<String, sea_orm::DbErr> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(trimmed.to_owned())
    } else {
        Err(sea_orm::DbErr::Custom(format!(
            "{env_name} must be exactly 64 hexadecimal characters"
        )))
    }
}

/// Write-once pin to the UUID of the single Master API key.
pub struct MasterPin {
    cell: OnceLock<Uuid>,
}

impl MasterPin {
    /// Creates an unpinned handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cell: OnceLock::new(),
        }
    }

    /// Creates a handle pre-pinned to `id` (used in tests).
    #[must_use]
    pub fn pinned_to(id: Uuid) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(id);
        Self { cell }
    }

    /// Returns the pinned Master UUID if set.
    #[must_use]
    pub fn get(&self) -> Option<Uuid> {
        self.cell.get().copied()
    }

    /// Pins the Master identity from the database at startup, refusing multiple Masters or a
    /// missing uniqueness index (`idx_api_keys_master_marker`).
    ///
    /// # Errors
    /// Returns [`sea_orm::DbErr`] if querying fails, 0 or >1 Master rows exist, or the uniqueness
    /// index is absent.
    pub async fn pin_at_boot(&self, db: &DatabaseConnection) -> Result<Uuid, sea_orm::DbErr> {
        if let Some(pinned) = self.cell.get() {
            return Ok(*pinned);
        }
        let masters: Vec<api_key::Model> = ApiKey::find()
            .filter(api_key::Column::IsMaster.eq(true))
            .all(db)
            .await?;
        let first = match masters.as_slice() {
            [] => return Err(sea_orm::DbErr::Custom("no Master key exists".to_owned())),
            [sole] => sole,
            many => {
                let ids: Vec<String> = many.iter().map(|m| m.id.to_string()).collect();
                return Err(sea_orm::DbErr::Custom(format!(
                    "multiple Master keys exist ({}); refusing to boot",
                    ids.join(", ")
                )));
            }
        };
        if !crate::db::has_index(db, API_KEYS_TABLE, MASTER_MARKER_INDEX).await? {
            return Err(sea_orm::DbErr::Custom(format!(
                "unique index '{MASTER_MARKER_INDEX}' is missing from '{API_KEYS_TABLE}'; re-run migrations"
            )));
        }
        let _ = self.cell.set(first.id);
        Ok(first.id)
    }

    /// Verifies that a key claiming `is_master = true` matches the pinned Master identity.
    pub fn authenticate(&self, key: &mut api_key::Model) {
        if !key.is_master {
            return;
        }
        if self.cell.get().copied() != Some(key.id) {
            tracing::error!(
                key_id = %key.id,
                "TAMPER: key claims is_master=true but does not match pinned Master identity; demoting"
            );
            key.is_master = false;
        }
    }
}

impl Default for MasterPin {
    fn default() -> Self {
        Self::new()
    }
}

/// Ensures a Master API key exists in `api_keys` (creating one from `INITIAL_MASTER_KEY` /
/// `INITIAL_MASTER_SIGNING_SECRET` or generating fresh 64-hex credentials at first boot).
///
/// # Errors
/// Returns [`sea_orm::DbErr`] if bootstrap environment secrets are malformed or persistence fails.
pub async fn ensure_master_key(
    db: &DatabaseConnection,
    cipher: &SecretCipher,
) -> Result<Uuid, sea_orm::DbErr> {
    if let Some(existing) = ApiKey::find()
        .filter(api_key::Column::IsMaster.eq(true))
        .one(db)
        .await?
    {
        return Ok(existing.id);
    }

    let raw_key = if let Some(val) =
        crate::config::get_secret_or_env(crate::config::INITIAL_MASTER_KEY_ENV)
    {
        validate_hex_64(crate::config::INITIAL_MASTER_KEY_ENV, &val)?
    } else if let Some(val) = crate::config::get_secret_or_env("MASTER_API_KEY") {
        validate_hex_64("MASTER_API_KEY", &val)?
    } else {
        generate_signing_secret()
    };

    let raw_secret = if let Some(val) =
        crate::config::get_secret_or_env(crate::config::INITIAL_MASTER_SIGNING_SECRET_ENV)
    {
        validate_hex_64(crate::config::INITIAL_MASTER_SIGNING_SECRET_ENV, &val)?
    } else if let Some(val) = crate::config::get_secret_or_env("MASTER_SIGNING_SECRET") {
        validate_hex_64("MASTER_SIGNING_SECRET", &val)?
    } else {
        generate_signing_secret()
    };

    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());
    let prefix: String = raw_key.chars().take(8).collect();
    let sealed_secret = cipher
        .seal(&raw_secret)
        .map_err(|e| sea_orm::DbErr::Custom(format!("failed to seal master secret: {e}")))?;

    let id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let model = api_key::ActiveModel {
        id: Set(id),
        name: Set("Master Key".to_owned()),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(sealed_secret)),
        prefix: Set(prefix),
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
    model.insert(db).await?;

    let border = "═".repeat(BANNER_WIDTH);
    let bound_ip = "ALL (Unrestricted)";
    let rows = [
        format!("X-API-Key      : {raw_key}"),
        format!("Signing secret : {raw_secret}"),
        format!("Bound IPs      : {bound_ip}"),
        String::new(),
        "Both values are needed to sign requests (X-Timestamp + X-Signature-256).".to_owned(),
        "They will NOT be shown again — store them securely!".to_owned(),
    ];
    let mut body = String::new();
    for row in rows {
        let _ = writeln!(body, "║ {row:<BANNER_WIDTH$} ║");
    }

    tracing::info!(
        "\n╔{border}╗\n║ {:<BANNER_WIDTH$} ║\n╠{border}╣\n{body}╚{border}╝",
        "BOOTSTRAP: Master API Key Generated"
    );

    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    Ok(id)
}

/// Verifies at boot that the configured encryption key can decrypt existing sealed secrets,
/// using the Master key's `signing_secret` as a canary.
///
/// # Errors
/// Returns an error message if decryption fails due to an encryption-key mismatch or database error.
pub async fn verify_encryption_key(
    db: &DatabaseConnection,
    cipher: &SecretCipher,
) -> Result<(), String> {
    let Some(master) = ApiKey::find()
        .filter(api_key::Column::IsMaster.eq(true))
        .one(db)
        .await
        .map_err(|e| format!("failed querying Master key canary: {e}"))?
    else {
        return Ok(());
    };
    let Some(stored) = master.signing_secret.as_deref() else {
        return Ok(());
    };
    cipher.open(stored).map_err(|e| {
        format!(
            "FW_ENCRYPTION_KEY does not match the key used to seal stored secrets ({e}); refusing to start"
        )
    })?;
    Ok(())
}
