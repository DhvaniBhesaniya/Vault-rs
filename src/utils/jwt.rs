use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

use crate::errors::AppError;

/// JWT claims for access tokens.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user_id)
    pub sub: String,
    /// Email
    pub email: String,
    /// Issued at (unix timestamp)
    pub iat: i64,
    /// Expiration (unix timestamp)
    pub exp: i64,
    /// JWT ID (unique identifier for this token)
    pub jti: String,
    /// Security stamp (rotated on password change)
    pub security_stamp: String,
    /// Token type: "access" or "refresh"
    pub token_type: String,
}

/// Create an access token JWT.
pub fn create_access_token(
    user_id: &ObjectId,
    email: &str,
    security_stamp: &str,
    secret: &str,
    expiry_secs: i64,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id.to_hex(),
        email: email.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(expiry_secs)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        security_stamp: security_stamp.to_string(),
        token_type: "access".to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Failed to create access token: {}", e)))
}

/// Create a refresh token JWT (longer-lived).
pub fn create_refresh_token(
    user_id: &ObjectId,
    email: &str,
    security_stamp: &str,
    secret: &str,
    expiry_secs: i64,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id.to_hex(),
        email: email.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(expiry_secs)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        security_stamp: security_stamp.to_string(),
        token_type: "refresh".to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Failed to create refresh token: {}", e)))
}

/// Validate and decode a JWT token.
pub fn validate_token(token: &str, secret: &str) -> Result<TokenData<Claims>, AppError> {
    let validation = Validation::default();

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| AppError::Unauthorized(format!("Invalid token: {}", e)))
}

/// Extract user_id from validated claims.
pub fn extract_user_id(claims: &Claims) -> Result<ObjectId, AppError> {
    ObjectId::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid user ID in token".to_string()))
}

/// Compute SHA-256 hash of a refresh token for storage.
pub fn hash_refresh_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
