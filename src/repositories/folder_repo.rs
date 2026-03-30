use chrono::Utc;
use futures::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId},
    Collection, Database,
};

use crate::errors::AppError;
use crate::models::folder::Folder;

/// Data access layer for the `folders` collection.
#[derive(Clone)]
pub struct FolderRepository {
    collection: Collection<Folder>,
}

impl FolderRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection::<Folder>("folders"),
        }
    }

    pub async fn create(&self, folder: &Folder) -> Result<String, AppError> {
        let result = self.collection.insert_one(folder).await?;
        Ok(result
            .inserted_id
            .as_object_id()
            .map(|id| id.to_hex())
            .unwrap_or_default())
    }

    pub async fn find_by_id(
        &self,
        folder_id: &ObjectId,
        user_id: &ObjectId,
    ) -> Result<Option<Folder>, AppError> {
        let folder = self
            .collection
            .find_one(doc! { "_id": folder_id, "user_id": user_id })
            .await?;
        Ok(folder)
    }

    pub async fn find_all_by_user(&self, user_id: &ObjectId) -> Result<Vec<Folder>, AppError> {
        let cursor = self
            .collection
            .find(doc! { "user_id": user_id })
            .await?;

        let folders: Vec<Folder> = cursor.try_collect().await?;
        Ok(folders)
    }

    pub async fn update_name(
        &self,
        folder_id: &ObjectId,
        user_id: &ObjectId,
        name_encrypted: &str,
    ) -> Result<bool, AppError> {
        let result = self
            .collection
            .update_one(
                doc! { "_id": folder_id, "user_id": user_id },
                doc! {
                    "$set": {
                        "name_encrypted": name_encrypted,
                        "updated_at": Utc::now().to_rfc3339()
                    }
                },
            )
            .await?;

        Ok(result.modified_count > 0)
    }

    pub async fn delete(
        &self,
        folder_id: &ObjectId,
        user_id: &ObjectId,
    ) -> Result<bool, AppError> {
        let result = self
            .collection
            .delete_one(doc! { "_id": folder_id, "user_id": user_id })
            .await?;

        Ok(result.deleted_count > 0)
    }
}
