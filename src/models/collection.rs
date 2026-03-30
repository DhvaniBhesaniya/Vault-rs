use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

/// A shared collection within an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub organization_id: ObjectId,

    /// AES-GCM encrypted collection name (base64)
    pub name_encrypted: String,

    /// Members assigned to this collection
    #[serde(default)]
    pub assigned_members: Vec<CollectionMember>,

    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionMember {
    pub user_id: ObjectId,
    pub read_only: bool,
}
