use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

/// An organization for team-based vault sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub name: String,
    pub owner_user_id: ObjectId,
    pub billing_email: Option<String>,

    /// Org symmetric key encrypted per-member with their RSA public key
    pub org_symmetric_key_encrypted: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
