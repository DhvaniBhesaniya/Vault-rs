use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

/// A folder for organizing vault items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub user_id: ObjectId,

    /// AES-GCM encrypted folder name (base64)
    pub name_encrypted: String,

    /// Optional parent folder for nesting
    pub parent_folder_id: Option<ObjectId>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
