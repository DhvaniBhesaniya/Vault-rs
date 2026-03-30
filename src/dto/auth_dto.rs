use serde::{Deserialize, Serialize};
use validator::Validate;

// ─── Registration ───

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,

    #[validate(length(min = 1, max = 100, message = "Name must be between 1 and 100 characters"))]
    pub name: String,

    /// Base64-encoded HKDF-derived master password hash (client computes this)
    #[validate(length(min = 1, message = "Master password hash is required"))]
    pub master_password_hash: String,

    /// Base64-encoded AES-GCM encrypted symmetric key
    #[validate(length(min = 1, message = "Protected symmetric key is required"))]
    pub protected_symmetric_key: String,

    /// Base64-encoded nonce for protected_symmetric_key
    #[validate(length(min = 1, message = "Protected symmetric key nonce is required"))]
    pub protected_symmetric_key_nonce: String,

    /// Optional base64-encoded encrypted RSA private key
    pub protected_private_key: Option<String>,
    pub protected_private_key_nonce: Option<String>,

    /// Optional base64-encoded RSA public key
    pub public_key: Option<String>,

    pub password_hint: Option<String>,

    /// KDF parameters used by the client
    pub kdf_memory_kb: Option<u32>,
    pub kdf_iterations: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub email: String,
    pub message: String,
}

// ─── Login ───

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,

    /// Base64-encoded HKDF-derived master password hash
    #[validate(length(min = 1, message = "Master password hash is required"))]
    pub master_password_hash: String,

    /// Device info for session tracking
    pub device_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,

    /// Protected symmetric key for client-side decryption
    pub protected_symmetric_key: String,
    pub protected_symmetric_key_nonce: String,

    /// User info
    pub user_id: String,
    pub email: String,
    pub name: String,

    /// Indicates if 2FA verification is still needed
    pub two_factor_required: bool,

    pub kdf_memory_kb: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
}

// ─── Token Refresh ───

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

// ─── 2FA ───

#[derive(Debug, Deserialize, Validate)]
pub struct TwoFactorLoginRequest {
    #[validate(length(equal = 6, message = "TOTP code must be 6 digits"))]
    pub totp_code: String,

    /// Temporary token from initial login
    pub pending_token: String,
}

// ─── Change Password ───

#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    /// Current master password hash
    #[validate(length(min = 1))]
    pub current_master_password_hash: String,

    /// New master password hash
    #[validate(length(min = 1))]
    pub new_master_password_hash: String,

    /// Re-encrypted symmetric key with the new master key
    #[validate(length(min = 1))]
    pub new_protected_symmetric_key: String,
    pub new_protected_symmetric_key_nonce: String,
}
