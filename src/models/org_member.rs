use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

/// Role within an organization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

/// Organization member status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OrgMemberStatus {
    Invited,
    Confirmed,
    Revoked,
}

/// Permissions for an organization member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgPermissions {
    pub manage_members: bool,
    pub manage_collections: bool,
    pub manage_policies: bool,
    pub export_vault: bool,
}

/// An organization member record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMember {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub organization_id: ObjectId,
    pub user_id: ObjectId,
    pub role: OrgRole,

    /// Org symmetric key encrypted with this user's RSA public key
    pub org_key_encrypted: Option<String>,

    pub status: OrgMemberStatus,
    pub permissions: OrgPermissions,

    pub invited_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}
