use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

/// Vault item type classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VaultItemType {
    Login,
    Card,
    Identity,
    SecureNote,
    SshKey,
    ApiCredential,
}

/// A vault item — all sensitive data is encrypted client-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub user_id: ObjectId,

    /// Null for personal items, set for organization items
    pub organization_id: Option<ObjectId>,

    /// Optional folder reference
    pub folder_id: Option<ObjectId>,

    pub item_type: VaultItemType,

    /// AES-GCM encrypted item name (base64)
    pub name_encrypted: String,

    /// AES-GCM encrypted JSON blob containing all sensitive fields (base64)
    pub data_encrypted: String,

    /// 96-bit nonce used for encryption (base64)
    pub nonce: String,

    pub favorite: bool,

    /// If true, require master password re-entry to view
    pub reprompt: bool,

    /// Plaintext tags for search/filtering
    #[serde(default)]
    pub tags: Vec<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    /// Soft delete timestamp (null if not deleted)
    pub deleted_at: Option<DateTime<Utc>>,
}
