use chrono::Utc;
use mongodb::{
    bson::{doc, oid::ObjectId},
    Collection, Database,
};
use futures::TryStreamExt;

use crate::errors::AppError;
use crate::models::vault_item::VaultItem;

/// Data access layer for the `vault_items` collection.
#[derive(Clone)]
pub struct VaultItemRepository {
    collection: Collection<VaultItem>,
}

impl VaultItemRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection::<VaultItem>("vault_items"),
        }
    }

    /// Create a new vault item.
    pub async fn create(&self, item: &VaultItem) -> Result<String, AppError> {
        let result = self.collection.insert_one(item).await?;
        Ok(result
            .inserted_id
            .as_object_id()
            .map(|id| id.to_hex())
            .unwrap_or_default())
    }

    /// Find a vault item by ID, ensuring it belongs to the given user.
    pub async fn find_by_id(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
    ) -> Result<Option<VaultItem>, AppError> {
        let item = self
            .collection
            .find_one(doc! {
                "_id": item_id,
                "user_id": user_id,
            })
            .await?;
        Ok(item)
    }

    /// List all non-deleted vault items for a user.
    pub async fn find_all_by_user(
        &self,
        user_id: &ObjectId,
        skip: u64,
        limit: i64,
    ) -> Result<Vec<VaultItem>, AppError> {
        let cursor = self
            .collection
            .find(doc! {
                "user_id": user_id,
                "deleted_at": null,
            })
            .skip(skip)
            .limit(limit)
            .await?;

        let items: Vec<VaultItem> = cursor.try_collect().await?;
        Ok(items)
    }

    /// Count all non-deleted vault items for a user.
    pub async fn count_by_user(&self, user_id: &ObjectId) -> Result<u64, AppError> {
        let count = self
            .collection
            .count_documents(doc! {
                "user_id": user_id,
                "deleted_at": null,
            })
            .await?;
        Ok(count)
    }

    /// Update a vault item.
    pub async fn update(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
        update_doc: mongodb::bson::Document,
    ) -> Result<bool, AppError> {
        let mut set_doc = update_doc;
        set_doc.insert("updated_at", Utc::now().to_rfc3339());

        let result = self
            .collection
            .update_one(
                doc! { "_id": item_id, "user_id": user_id },
                doc! { "$set": set_doc },
            )
            .await?;

        Ok(result.modified_count > 0)
    }

    /// Soft delete a vault item (move to trash).
    pub async fn soft_delete(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
    ) -> Result<bool, AppError> {
        let result = self
            .collection
            .update_one(
                doc! { "_id": item_id, "user_id": user_id, "deleted_at": null },
                doc! {
                    "$set": {
                        "deleted_at": Utc::now().to_rfc3339(),
                        "updated_at": Utc::now().to_rfc3339()
                    }
                },
            )
            .await?;

        Ok(result.modified_count > 0)
    }

    /// Restore a soft-deleted vault item from trash.
    pub async fn restore(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
    ) -> Result<bool, AppError> {
        let result = self
            .collection
            .update_one(
                doc! {
                    "_id": item_id,
                    "user_id": user_id,
                    "deleted_at": { "$ne": null }
                },
                doc! {
                    "$set": {
                        "deleted_at": null,
                        "updated_at": Utc::now().to_rfc3339()
                    }
                },
            )
            .await?;

        Ok(result.modified_count > 0)
    }

    /// Permanently delete a vault item.
    pub async fn permanent_delete(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
    ) -> Result<bool, AppError> {
        let result = self
            .collection
            .delete_one(doc! { "_id": item_id, "user_id": user_id })
            .await?;

        Ok(result.deleted_count > 0)
    }

    /// List trashed (soft-deleted) items for a user.
    pub async fn find_trashed(
        &self,
        user_id: &ObjectId,
    ) -> Result<Vec<VaultItem>, AppError> {
        let cursor = self
            .collection
            .find(doc! {
                "user_id": user_id,
                "deleted_at": { "$ne": null },
            })
            .await?;

        let items: Vec<VaultItem> = cursor.try_collect().await?;
        Ok(items)
    }

    /// Ensure indexes on the vault_items collection.
    pub async fn ensure_indexes(&self) -> Result<(), AppError> {
        use mongodb::IndexModel;

        let indexes = vec![
            IndexModel::builder()
                .keys(doc! { "user_id": 1, "deleted_at": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "organization_id": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "folder_id": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "user_id": 1, "item_type": 1 })
                .build(),
        ];

        self.collection.create_indexes(indexes).await?;
        Ok(())
    }
}
