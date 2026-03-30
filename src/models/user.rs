use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

/// KDF parameters stored per user for key derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_kb: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            memory_kb: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// Two-factor authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorConfig {
    pub enabled: bool,
    pub totp_secret_encrypted: Option<String>,
    pub recovery_codes_encrypted: Option<String>,
}

impl Default for TwoFactorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            totp_secret_encrypted: None,
            recovery_codes_encrypted: None,
        }
    }
}

/// Account status enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Active,
    Locked,
    Suspended,
}

/// The User model, stored in the `users` collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub email: String,
    pub name: String,

    /// Argon2id(HKDF(master_key, master_password)) — server-side double hash
    pub master_password_hash: String,

    /// AES-GCM encrypted symmetric key (encrypted by master key)
    pub protected_symmetric_key: String,

    /// Nonce used for protected_symmetric_key encryption
    pub protected_symmetric_key_nonce: String,

    /// AES-GCM encrypted RSA private key (encrypted by symmetric key)
    pub protected_private_key: Option<String>,

    /// Nonce for protected_private_key encryption
    pub protected_private_key_nonce: Option<String>,

    /// RSA-4096 public key (plaintext, base64 encoded)
    pub public_key: Option<String>,

    /// Key derivation function parameters
    pub kdf_params: KdfParams,

    /// Two-factor authentication configuration
    pub two_factor: TwoFactorConfig,

    /// Rotated on password change; invalidates all sessions
    pub security_stamp: String,

    pub account_status: AccountStatus,
    pub failed_login_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
    pub password_hint: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
