//! Shared application state.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use sea_orm::DatabaseConnection;

use crate::config::TrustedProxies;
use crate::crypto::SecretCipher;
use crate::master::MasterPin;
use crate::replay::ReplayGuard;

/// Shared, cloneable application state passed to every HTTP handler.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool.
    pub db: DatabaseConnection,
    /// Secrets-at-rest cipher.
    pub cipher: Arc<SecretCipher>,
    /// Inbound anti-replay guard.
    pub replay: Arc<ReplayGuard>,
    /// Master identity pin.
    pub master_pin: Arc<MasterPin>,
    /// Trusted reverse proxies.
    pub trusted_proxies: TrustedProxies,
    /// Outbound HTTP client for blocklist feed testing, Docker HTTP API, and `simply_hook_executor`.
    pub http: Client,
}

impl AppState {
    /// Builds application state from a database connection and environment variables.
    ///
    /// # Errors
    /// Returns an error string if the encryption key or HTTP client cannot be initialized.
    pub fn new(db: DatabaseConnection) -> Result<Self, String> {
        let cipher = SecretCipher::from_env().map_err(|e| e.to_string())?;
        let trusted_proxies = TrustedProxies::from_env();
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            db,
            cipher: Arc::new(cipher),
            replay: Arc::new(ReplayGuard::default()),
            master_pin: Arc::new(MasterPin::new()),
            trusted_proxies,
            http,
        })
    }

    /// Builds application state for automated tests with a pre-pinned Master key.
    ///
    /// # Errors
    /// Returns an error if the HTTP client fails to initialize.
    pub fn for_tests(db: DatabaseConnection, master_id: uuid::Uuid) -> Result<Self, String> {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            db,
            cipher: Arc::new(SecretCipher::Plaintext),
            replay: Arc::new(ReplayGuard::default()),
            master_pin: Arc::new(MasterPin::pinned_to(master_id)),
            trusted_proxies: TrustedProxies::default(),
            http,
        })
    }
}
