use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::models::vault_item::VaultItemType;

// ─── Create Vault Item ───

#[derive(Debug, Deserialize, Validate)]
pub struct CreateVaultItemRequest {
    pub item_type: VaultItemType,

    #[validate(length(min = 1, message = "Encrypted name is required"))]
    pub name_encrypted: String,

    #[validate(length(min = 1, message = "Encrypted data is required"))]
    pub data_encrypted: String,

    #[validate(length(min = 1, message = "Nonce is required"))]
    pub nonce: String,

    pub folder_id: Option<String>,

    #[serde(default)]
    pub favorite: bool,

    #[serde(default)]
    pub reprompt: bool,

    #[serde(default)]
    pub tags: Vec<String>,
}

// ─── Update Vault Item ───

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateVaultItemRequest {
    pub item_type: Option<VaultItemType>,
    pub name_encrypted: Option<String>,
    pub data_encrypted: Option<String>,
    pub nonce: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: Option<bool>,
    pub reprompt: Option<bool>,
    pub tags: Option<Vec<String>>,
}

// ─── Vault Item Response ───

#[derive(Debug, Serialize)]
pub struct VaultItemResponse {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    pub item_type: VaultItemType,
    pub name_encrypted: String,
    pub data_encrypted: String,
    pub nonce: String,
    pub favorite: bool,
    pub reprompt: bool,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

impl From<crate::models::vault_item::VaultItem> for VaultItemResponse {
    fn from(item: crate::models::vault_item::VaultItem) -> Self {
        Self {
            id: item.id.map(|id| id.to_hex()).unwrap_or_default(),
            user_id: item.user_id.to_hex(),
            organization_id: item.organization_id.map(|id| id.to_hex()),
            folder_id: item.folder_id.map(|id| id.to_hex()),
            item_type: item.item_type,
            name_encrypted: item.name_encrypted,
            data_encrypted: item.data_encrypted,
            nonce: item.nonce,
            favorite: item.favorite,
            reprompt: item.reprompt,
            tags: item.tags,
            created_at: item.created_at.to_rfc3339(),
            updated_at: item.updated_at.to_rfc3339(),
            deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
        }
    }
}

// ─── Password Generator ───

#[derive(Debug, Deserialize)]
pub struct GeneratePasswordRequest {
    pub length: Option<usize>,
    pub uppercase: Option<bool>,
    pub lowercase: Option<bool>,
    pub numbers: Option<bool>,
    pub symbols: Option<bool>,
    pub exclude_ambiguous: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct GeneratePasswordResponse {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct GeneratePassphraseRequest {
    pub num_words: Option<usize>,
    pub separator: Option<String>,
    pub capitalize: Option<bool>,
    pub include_number: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct GeneratePassphraseResponse {
    pub passphrase: String,
}

/// Breach check using k-Anonymity (HIBP API).
#[derive(Debug, Deserialize)]
pub struct CheckBreachRequest {
    /// SHA-1 hash of the password (client computes this)
    pub sha1_hash: String,
}

#[derive(Debug, Serialize)]
pub struct CheckBreachResponse {
    pub breached: bool,
    pub count: u64,
}
