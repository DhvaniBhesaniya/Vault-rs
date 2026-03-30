use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{Duration, Utc};
use mongodb::bson::oid::ObjectId;

use crate::config::Settings;
use crate::crypto;
use crate::dto::auth_dto::*;
use crate::errors::AppError;
use crate::models::audit_log::{AuditAction, AuditLog};
use crate::models::session::{DeviceInfo, Session};
use crate::models::user::{AccountStatus, KdfParams, TwoFactorConfig, User};
use crate::repositories::audit_log_repo::AuditLogRepository;
use crate::repositories::session_repo::SessionRepository;
use crate::repositories::user_repo::UserRepository;
use crate::utils::jwt;

/// Authentication service handling registration, login, and token management.
#[derive(Clone)]
pub struct AuthService {
    pub user_repo: UserRepository,
    pub session_repo: SessionRepository,
    pub audit_repo: AuditLogRepository,
    pub settings: Arc<Settings>,
}

impl AuthService {
    pub fn new(
        user_repo: UserRepository,
        session_repo: SessionRepository,
        audit_repo: AuditLogRepository,
        settings: Arc<Settings>,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            audit_repo,
            settings,
        }
    }

    /// Register a new user.
    pub async fn register(
        &self,
        req: RegisterRequest,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<RegisterResponse, AppError> {
        // Check if user already exists
        if self.user_repo.find_by_email(&req.email).await?.is_some() {
            return Err(AppError::Conflict(
                "An account with this email already exists".to_string(),
            ));
        }

        // Decode the client-provided master_password_hash (base64)
        let master_pw_hash_bytes = BASE64
            .decode(&req.master_password_hash)
            .map_err(|_| AppError::Validation("Invalid base64 in master_password_hash".to_string()))?;

        // Server-side: hash the master_pw_hash again with Argon2id for storage
        let stored_hash = crypto::argon2::hash_for_storage(
            &master_pw_hash_bytes,
            self.settings.argon2_memory_kb,
            self.settings.argon2_iterations,
            self.settings.argon2_parallelism,
        )?;

        let now = Utc::now();
        let user = User {
            id: None,
            email: req.email.to_lowercase(),
            name: req.name,
            master_password_hash: stored_hash,
            protected_symmetric_key: req.protected_symmetric_key,
            protected_symmetric_key_nonce: req.protected_symmetric_key_nonce,
            protected_private_key: req.protected_private_key,
            protected_private_key_nonce: req.protected_private_key_nonce,
            public_key: req.public_key,
            kdf_params: KdfParams {
                algorithm: "argon2id".to_string(),
                memory_kb: req.kdf_memory_kb.unwrap_or(65536),
                iterations: req.kdf_iterations.unwrap_or(3),
                parallelism: req.kdf_parallelism.unwrap_or(4),
            },
            two_factor: TwoFactorConfig::default(),
            security_stamp: uuid::Uuid::new_v4().to_string(),
            account_status: AccountStatus::Active,
            failed_login_attempts: 0,
            locked_until: None,
            password_hint: req.password_hint,
            created_at: now,
            updated_at: now,
        };

        let user_id = self.user_repo.create(&user).await?;

        // Audit log
        let user_oid = ObjectId::parse_str(&user_id)
            .map_err(|_| AppError::Internal("Failed to parse user ID".to_string()))?;
        self.audit_repo
            .create(&AuditLog {
                id: None,
                user_id: user_oid,
                organization_id: None,
                action: AuditAction::AuthRegister,
                resource_type: Some("user".to_string()),
                resource_id: Some(user_oid),
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                metadata: serde_json::json!({}),
                timestamp: now,
            })
            .await?;

        Ok(RegisterResponse {
            user_id,
            email: user.email,
            message: "Account created successfully".to_string(),
        })
    }

    /// Login with email and master password hash.
    pub async fn login(
        &self,
        req: LoginRequest,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<LoginResponse, AppError> {
        let user = self
            .user_repo
            .find_by_email(&req.email)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

        let user_id = user.id.ok_or_else(|| {
            AppError::Internal("User has no ID".to_string())
        })?;

        // Check account lock
        if user.account_status == AccountStatus::Locked {
            if let Some(locked_until) = user.locked_until {
                if Utc::now() < locked_until {
                    return Err(AppError::AccountLocked(locked_until.to_rfc3339()));
                }
                // Lock expired, reset
                self.user_repo.reset_failed_logins(&user_id).await?;
            }
        }

        // Verify master password hash
        let master_pw_hash_bytes = BASE64
            .decode(&req.master_password_hash)
            .map_err(|_| AppError::Validation("Invalid base64 in master_password_hash".to_string()))?;

        let is_valid = crypto::argon2::verify_hash(
            &master_pw_hash_bytes,
            &user.master_password_hash,
        )?;

        if !is_valid {
            // Increment failed login attempts
            let new_count = user.failed_login_attempts + 1;
            let locked_until = if new_count >= self.settings.max_failed_login_attempts {
                Some(Utc::now() + Duration::seconds(self.settings.lockout_duration_secs as i64))
            } else {
                None
            };

            self.user_repo
                .increment_failed_logins(&user_id, locked_until)
                .await?;

            // Audit failed login
            self.audit_repo
                .create(&AuditLog {
                    id: None,
                    user_id,
                    organization_id: None,
                    action: AuditAction::AuthFailedLogin,
                    resource_type: None,
                    resource_id: None,
                    ip_address: ip_address.to_string(),
                    user_agent: user_agent.map(|s| s.to_string()),
                    metadata: serde_json::json!({ "attempt": new_count }),
                    timestamp: Utc::now(),
                })
                .await?;

            return Err(AppError::Unauthorized("Invalid email or password".to_string()));
        }

        // Reset failed login counter on success
        self.user_repo.reset_failed_logins(&user_id).await?;

        // Check if 2FA is enabled
        if user.two_factor.enabled {
            // TODO: Return a temporary token for 2FA flow
            // For now, we'll skip this and proceed with login
        }

        // Create tokens
        let access_token = jwt::create_access_token(
            &user_id,
            &user.email,
            &user.security_stamp,
            &self.settings.jwt_secret,
            self.settings.jwt_access_token_expiry_secs,
        )?;

        let refresh_token = jwt::create_refresh_token(
            &user_id,
            &user.email,
            &user.security_stamp,
            &self.settings.jwt_secret,
            self.settings.jwt_refresh_token_expiry_secs,
        )?;

        // Store session
        let session = Session {
            id: None,
            user_id,
            refresh_token_hash: jwt::hash_refresh_token(&refresh_token),
            device_info: DeviceInfo {
                name: req.device_name.clone(),
                ip: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
            },
            created_at: Utc::now(),
            expires_at: Utc::now()
                + Duration::seconds(self.settings.jwt_refresh_token_expiry_secs),
            last_used_at: Utc::now(),
            revoked: false,
        };
        self.session_repo.create(&session).await?;

        // Audit successful login
        self.audit_repo
            .create(&AuditLog {
                id: None,
                user_id,
                organization_id: None,
                action: AuditAction::AuthLogin,
                resource_type: None,
                resource_id: None,
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                metadata: serde_json::json!({}),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(LoginResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.settings.jwt_access_token_expiry_secs,
            protected_symmetric_key: user.protected_symmetric_key,
            protected_symmetric_key_nonce: user.protected_symmetric_key_nonce,
            user_id: user_id.to_hex(),
            email: user.email,
            name: user.name,
            two_factor_required: false,
            kdf_memory_kb: user.kdf_params.memory_kb,
            kdf_iterations: user.kdf_params.iterations,
            kdf_parallelism: user.kdf_params.parallelism,
        })
    }

    /// Refresh an access token using a refresh token.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<RefreshTokenResponse, AppError> {
        // Validate the refresh token JWT
        let token_data = jwt::validate_token(refresh_token, &self.settings.jwt_secret)?;
        let claims = token_data.claims;

        if claims.token_type != "refresh" {
            return Err(AppError::Unauthorized("Invalid token type".to_string()));
        }

        let user_id = jwt::extract_user_id(&claims)?;

        // Check session exists and is not revoked
        let token_hash = jwt::hash_refresh_token(refresh_token);
        let session = self
            .session_repo
            .find_by_refresh_token_hash(&token_hash)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Session not found or revoked".to_string()))?;

        // Load user to verify security stamp
        let user = self
            .user_repo
            .find_by_id(&user_id)
            .await?
            .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

        if user.security_stamp != claims.security_stamp {
            // Security stamp changed (password changed), invalidate this session
            if let Some(session_id) = session.id {
                self.session_repo.revoke(&session_id).await?;
            }
            return Err(AppError::Unauthorized(
                "Session invalidated due to security change".to_string(),
            ));
        }

        // Revoke old session, create new one (token rotation)
        if let Some(session_id) = session.id {
            self.session_repo.revoke(&session_id).await?;
        }

        // Create new tokens
        let new_access_token = jwt::create_access_token(
            &user_id,
            &user.email,
            &user.security_stamp,
            &self.settings.jwt_secret,
            self.settings.jwt_access_token_expiry_secs,
        )?;

        let new_refresh_token = jwt::create_refresh_token(
            &user_id,
            &user.email,
            &user.security_stamp,
            &self.settings.jwt_secret,
            self.settings.jwt_refresh_token_expiry_secs,
        )?;

        // Create new session
        let new_session = Session {
            id: None,
            user_id,
            refresh_token_hash: jwt::hash_refresh_token(&new_refresh_token),
            device_info: session.device_info,
            created_at: Utc::now(),
            expires_at: Utc::now()
                + Duration::seconds(self.settings.jwt_refresh_token_expiry_secs),
            last_used_at: Utc::now(),
            revoked: false,
        };
        self.session_repo.create(&new_session).await?;

        Ok(RefreshTokenResponse {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.settings.jwt_access_token_expiry_secs,
        })
    }

    /// Logout (revoke current session).
    pub async fn logout(
        &self,
        refresh_token: &str,
        user_id: &ObjectId,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<(), AppError> {
        let token_hash = jwt::hash_refresh_token(refresh_token);
        if let Some(session) = self
            .session_repo
            .find_by_refresh_token_hash(&token_hash)
            .await?
        {
            if let Some(session_id) = session.id {
                self.session_repo.revoke(&session_id).await?;
            }
        }

        // Audit
        self.audit_repo
            .create(&AuditLog {
                id: None,
                user_id: *user_id,
                organization_id: None,
                action: AuditAction::AuthLogout,
                resource_type: None,
                resource_id: None,
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                metadata: serde_json::json!({}),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(())
    }

    /// Logout all sessions for a user.
    pub async fn logout_all(
        &self,
        user_id: &ObjectId,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<u64, AppError> {
        let count = self.session_repo.revoke_all_for_user(user_id).await?;

        self.audit_repo
            .create(&AuditLog {
                id: None,
                user_id: *user_id,
                organization_id: None,
                action: AuditAction::SessionRevoked,
                resource_type: None,
                resource_id: None,
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                metadata: serde_json::json!({ "sessions_revoked": count }),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(count)
    }
}
