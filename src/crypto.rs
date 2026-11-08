//! At-rest encryption (`SecretCipher`) and `CANONICAL_V1` HMAC-SHA256 request signing.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;

/// Maximum permitted clock skew, in seconds, for the symmetric freshness window.
pub const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;

/// Environment variable carrying the 64 hex character XChaCha20-Poly1305 key.
/// Also accepts `SYNC_ENCRYPTION_KEY` or `VAULT_ENCRYPTION_KEY` for operator convenience.
pub const ENCRYPTION_KEY_ENV: &str = "FW_ENCRYPTION_KEY";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const PLAINTEXT_PREFIX: &str = "v1.plain.";
const SEALED_PREFIX: &str = "v1.xchacha20poly1305.";

/// Required prefix on the `X-Signature-256` header value.
pub const SIGNATURE_PREFIX: &str = "sha256=";

/// Failure modes for [`SecretCipher`] operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Configured encryption key is not 64 hex characters.
    #[error("invalid encryption key")]
    InvalidKey,
    /// Stored secret does not carry a recognised envelope prefix or is corrupt.
    #[error("malformed ciphertext")]
    MalformedCiphertext,
    /// AEAD decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,
    /// AEAD encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,
}

/// Generates a fresh 256-bit HMAC signing secret, hex-encoded.
#[must_use]
pub fn generate_signing_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Builds the `CANONICAL_V1` byte string: `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`.
#[must_use]
pub fn canonical_v1_payload(method: &str, target: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(method.len() + target.len() + timestamp.len() + body.len() + 3);
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(target.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(body);
    message
}

/// Computes `sha256=<hex>` over the `CANONICAL_V1` payload using `secret`.
///
/// # Errors
/// Returns [`CryptoError::EncryptionFailed`] if HMAC initialization fails.
pub fn compute_signature(
    secret: &str,
    method: &str,
    target: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<String, CryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| {
        tracing::error!("failed to build HMAC from signing secret: {e}");
        CryptoError::EncryptionFailed
    })?;
    mac.update(&canonical_v1_payload(method, target, timestamp, body));
    Ok(format!(
        "{SIGNATURE_PREFIX}{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

/// Verifies a provided `X-Signature-256` value in constant time.
#[must_use]
pub fn verify_signature(
    secret: &str,
    method: &str,
    target: &str,
    timestamp: &str,
    body: &[u8],
    provided: &str,
) -> Option<Vec<u8>> {
    let raw_hex = provided
        .trim()
        .strip_prefix(SIGNATURE_PREFIX)
        .unwrap_or_else(|| provided.trim());
    let provided_bytes = hex::decode(raw_hex).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(&canonical_v1_payload(method, target, timestamp, body));
    mac.verify_slice(&provided_bytes).ok()?;
    Some(provided_bytes)
}

/// Seals and opens secrets at rest.
pub enum SecretCipher {
    /// No encryption key configured; secrets are stored hex-encoded under `v1.plain.`.
    Plaintext,
    /// XChaCha20-Poly1305 sealing is active.
    Sealed(Box<XChaCha20Poly1305>),
}

impl SecretCipher {
    /// Builds a cipher from `FW_ENCRYPTION_KEY` (or `SYNC_ENCRYPTION_KEY`).
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKey`] if the key is present but not 64 hex chars.
    pub fn from_env() -> Result<Self, CryptoError> {
        let configured = std::env::var(ENCRYPTION_KEY_ENV)
            .or_else(|_| std::env::var("SYNC_ENCRYPTION_KEY"))
            .ok()
            .filter(|raw| !raw.trim().is_empty());
        match configured {
            Some(raw) => Self::from_hex_key(raw.trim()),
            None => Ok(Self::Plaintext),
        }
    }

    /// Builds a `Sealed` cipher directly from a 64 hex character key.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKey`] if `hex_key` is not 64 hex chars.
    pub fn from_hex_key(hex_key: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_key).map_err(|_| CryptoError::InvalidKey)?;
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let key = chacha20poly1305::Key::try_from(bytes.as_slice())
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::Sealed(Box::new(XChaCha20Poly1305::new(&key))))
    }

    /// True when this cipher encrypts with XChaCha20-Poly1305.
    #[must_use]
    pub fn is_encrypting(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }

    /// Seals `plaintext` into its stored envelope.
    ///
    /// # Errors
    /// Returns [`CryptoError::EncryptionFailed`] if encryption fails.
    pub fn seal(&self, plaintext: &str) -> Result<String, CryptoError> {
        match self {
            Self::Plaintext => Ok(format!("{PLAINTEXT_PREFIX}{}", hex::encode(plaintext))),
            Self::Sealed(cipher) => {
                let nonce_bytes: [u8; NONCE_LEN] = rand::rng().random();
                let nonce = XNonce::from(nonce_bytes);
                let ciphertext = cipher
                    .encrypt(&nonce, plaintext.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed)?;
                Ok(format!(
                    "{SEALED_PREFIX}{}.{}",
                    hex::encode(nonce_bytes),
                    hex::encode(ciphertext)
                ))
            }
        }
    }

    /// Opens a stored envelope back into plaintext.
    ///
    /// # Errors
    /// Returns [`CryptoError`] if the envelope is malformed or cannot be decrypted.
    pub fn open(&self, stored: &str) -> Result<String, CryptoError> {
        if let Some(encoded) = stored.strip_prefix(PLAINTEXT_PREFIX) {
            let bytes = hex::decode(encoded).map_err(|_| CryptoError::MalformedCiphertext)?;
            return String::from_utf8(bytes).map_err(|_| CryptoError::MalformedCiphertext);
        }
        if let Some(body) = stored.strip_prefix(SEALED_PREFIX) {
            let (nonce_hex, ciphertext_hex) = body
                .split_once('.')
                .ok_or(CryptoError::MalformedCiphertext)?;
            let nonce_bytes =
                hex::decode(nonce_hex).map_err(|_| CryptoError::MalformedCiphertext)?;
            if nonce_bytes.len() != NONCE_LEN {
                return Err(CryptoError::MalformedCiphertext);
            }
            let ciphertext =
                hex::decode(ciphertext_hex).map_err(|_| CryptoError::MalformedCiphertext)?;
            let Self::Sealed(cipher) = self else {
                return Err(CryptoError::DecryptionFailed);
            };
            let nonce = XNonce::try_from(nonce_bytes.as_slice())
                .map_err(|_| CryptoError::MalformedCiphertext)?;
            let plaintext = cipher
                .decrypt(&nonce, ciphertext.as_ref())
                .map_err(|_| CryptoError::DecryptionFailed)?;
            return String::from_utf8(plaintext).map_err(|_| CryptoError::MalformedCiphertext);
        }
        Err(CryptoError::MalformedCiphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = generate_signing_secret();
        let cipher = SecretCipher::from_hex_key(&key).unwrap();
        let sealed = cipher.seal("secret-123").unwrap();
        assert_eq!(cipher.open(&sealed).unwrap(), "secret-123");
    }
}
