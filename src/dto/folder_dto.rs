use serde::{Deserialize, Serialize};
use validator::Validate;

// ─── Create Folder ───

#[derive(Debug, Deserialize, Validate)]
pub struct CreateFolderRequest {
    #[validate(length(min = 1, message = "Encrypted folder name is required"))]
    pub name_encrypted: String,

    pub parent_folder_id: Option<String>,
}

// ─── Update Folder ───

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateFolderRequest {
    #[validate(length(min = 1, message = "Encrypted folder name is required"))]
    pub name_encrypted: String,
}

// ─── Folder Response ───

#[derive(Debug, Serialize)]
pub struct FolderResponse {
    pub id: String,
    pub user_id: String,
    pub name_encrypted: String,
    pub parent_folder_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<crate::models::folder::Folder> for FolderResponse {
    fn from(folder: crate::models::folder::Folder) -> Self {
        Self {
            id: folder.id.map(|id| id.to_hex()).unwrap_or_default(),
            user_id: folder.user_id.to_hex(),
            name_encrypted: folder.name_encrypted,
            parent_folder_id: folder.parent_folder_id.map(|id| id.to_hex()),
            created_at: folder.created_at.to_rfc3339(),
            updated_at: folder.updated_at.to_rfc3339(),
        }
    }
}
