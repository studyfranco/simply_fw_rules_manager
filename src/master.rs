//! Master API key identity pinning and bootstrap seeding.

use std::sync::OnceLock;

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::{SecretCipher, generate_signing_secret};
use crate::entities::api_key;
use crate::entities::prelude::ApiKey;

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

    /// Pins the Master identity from the database at startup.
    ///
    /// # Errors
    /// Returns [`sea_orm::DbErr`] if the database query fails or no Master row exists.
    pub async fn pin_at_boot(&self, db: &DatabaseConnection) -> Result<Uuid, sea_orm::DbErr> {
        if let Some(pinned) = self.cell.get() {
            return Ok(*pinned);
        }
        let masters: Vec<api_key::Model> = ApiKey::find()
            .filter(api_key::Column::IsMaster.eq(true))
            .all(db)
            .await?;
        let Some(first) = masters.first() else {
            return Err(sea_orm::DbErr::Custom("no Master key exists".to_owned()));
        };
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
/// Returns [`sea_orm::DbErr`] if querying or inserting the Master key fails.
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

    let raw_key = std::env::var(crate::config::INITIAL_MASTER_KEY_ENV)
        .or_else(|_| std::env::var("MASTER_API_KEY"))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(generate_signing_secret);

    let raw_secret = std::env::var(crate::config::INITIAL_MASTER_SIGNING_SECRET_ENV)
        .or_else(|_| std::env::var("MASTER_SIGNING_SECRET"))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(generate_signing_secret);

    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());
    let prefix: String = raw_key.chars().take(8).collect();
    let sealed_secret = cipher
        .seal(&raw_secret)
        .map_err(|e| sea_orm::DbErr::Custom(format!("failed to seal master secret: {e}")))?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let model = api_key::ActiveModel {
        id: Set(id),
        name: Set("Master Key".to_owned()),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(sealed_secret)),
        prefix: Set(prefix),
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
    model.insert(db).await?;

    tracing::warn!(
        "Bootstrapped initial Master API Key (id={id}): API_KEY={raw_key} SIGNING_SECRET={raw_secret}"
    );
    Ok(id)
}
