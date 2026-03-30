use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

/// Audit log action types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    #[serde(rename = "auth.login")]
    AuthLogin,
    #[serde(rename = "auth.logout")]
    AuthLogout,
    #[serde(rename = "auth.failed_login")]
    AuthFailedLogin,
    #[serde(rename = "auth.register")]
    AuthRegister,
    #[serde(rename = "vault_item.create")]
    VaultItemCreate,
    #[serde(rename = "vault_item.read")]
    VaultItemRead,
    #[serde(rename = "vault_item.update")]
    VaultItemUpdate,
    #[serde(rename = "vault_item.delete")]
    VaultItemDelete,
    #[serde(rename = "password.changed")]
    PasswordChanged,
    #[serde(rename = "2fa.enabled")]
    TwoFaEnabled,
    #[serde(rename = "2fa.disabled")]
    TwoFaDisabled,
    #[serde(rename = "org.member_added")]
    OrgMemberAdded,
    #[serde(rename = "org.member_removed")]
    OrgMemberRemoved,
    #[serde(rename = "export.requested")]
    ExportRequested,
    #[serde(rename = "session.revoked")]
    SessionRevoked,
}

/// Immutable audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub user_id: ObjectId,
    pub organization_id: Option<ObjectId>,
    pub action: AuditAction,
    pub resource_type: Option<String>,
    pub resource_id: Option<ObjectId>,
    pub ip_address: String,
    pub user_agent: Option<String>,

    /// Action-specific metadata
    #[serde(default)]
    pub metadata: serde_json::Value,

    pub timestamp: DateTime<Utc>,
}
