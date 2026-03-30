use chrono::Utc;
use mongodb::bson::oid::ObjectId;

use crate::dto::folder_dto::*;
use crate::errors::AppError;
use crate::models::folder::Folder;
use crate::repositories::folder_repo::FolderRepository;
use crate::utils::validation::validate_object_id;

/// Folder service for organizing vault items.
#[derive(Clone)]
pub struct FolderService {
    pub folder_repo: FolderRepository,
}

impl FolderService {
    pub fn new(folder_repo: FolderRepository) -> Self {
        Self { folder_repo }
    }

    pub async fn create_folder(
        &self,
        user_id: &ObjectId,
        req: CreateFolderRequest,
    ) -> Result<FolderResponse, AppError> {
        let parent_id = req
            .parent_folder_id
            .as_deref()
            .map(validate_object_id)
            .transpose()?;

        let now = Utc::now();
        let folder = Folder {
            id: None,
            user_id: *user_id,
            name_encrypted: req.name_encrypted,
            parent_folder_id: parent_id,
            created_at: now,
            updated_at: now,
        };

        let folder_id_str = self.folder_repo.create(&folder).await?;
        let folder_id = ObjectId::parse_str(&folder_id_str)
            .map_err(|_| AppError::Internal("Failed to parse folder ID".to_string()))?;

        let mut created_folder = folder;
        created_folder.id = Some(folder_id);
        Ok(FolderResponse::from(created_folder))
    }

    pub async fn list_folders(
        &self,
        user_id: &ObjectId,
    ) -> Result<Vec<FolderResponse>, AppError> {
        let folders = self.folder_repo.find_all_by_user(user_id).await?;
        Ok(folders.into_iter().map(FolderResponse::from).collect())
    }

    pub async fn update_folder(
        &self,
        folder_id: &ObjectId,
        user_id: &ObjectId,
        req: UpdateFolderRequest,
    ) -> Result<(), AppError> {
        let updated = self
            .folder_repo
            .update_name(folder_id, user_id, &req.name_encrypted)
            .await?;

        if !updated {
            return Err(AppError::NotFound("Folder not found".to_string()));
        }
        Ok(())
    }

    pub async fn delete_folder(
        &self,
        folder_id: &ObjectId,
        user_id: &ObjectId,
    ) -> Result<(), AppError> {
        let deleted = self.folder_repo.delete(folder_id, user_id).await?;
        if !deleted {
            return Err(AppError::NotFound("Folder not found".to_string()));
        }
        Ok(())
    }
}
