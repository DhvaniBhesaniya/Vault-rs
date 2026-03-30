use chrono::Utc;
use mongodb::bson::oid::ObjectId;

use crate::dto::vault_dto::*;
use crate::errors::AppError;
use crate::models::audit_log::{AuditAction, AuditLog};
use crate::models::vault_item::VaultItem;
use crate::repositories::audit_log_repo::AuditLogRepository;
use crate::repositories::vault_item_repo::VaultItemRepository;
use crate::utils::validation::validate_object_id;

/// Vault service handling CRUD operations for vault items.
#[derive(Clone)]
pub struct VaultService {
    pub vault_repo: VaultItemRepository,
    pub audit_repo: AuditLogRepository,
}

impl VaultService {
    pub fn new(vault_repo: VaultItemRepository, audit_repo: AuditLogRepository) -> Self {
        Self {
            vault_repo,
            audit_repo,
        }
    }

    /// Create a new vault item.
    pub async fn create_item(
        &self,
        user_id: &ObjectId,
        req: CreateVaultItemRequest,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<VaultItemResponse, AppError> {
        let folder_id = req
            .folder_id
            .as_deref()
            .map(validate_object_id)
            .transpose()?;

        let now = Utc::now();
        let item = VaultItem {
            id: None,
            user_id: *user_id,
            organization_id: None,
            folder_id,
            item_type: req.item_type,
            name_encrypted: req.name_encrypted,
            data_encrypted: req.data_encrypted,
            nonce: req.nonce,
            favorite: req.favorite,
            reprompt: req.reprompt,
            tags: req.tags,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let item_id_str = self.vault_repo.create(&item).await?;
        let item_id = ObjectId::parse_str(&item_id_str)
            .map_err(|_| AppError::Internal("Failed to parse item ID".to_string()))?;

        // Audit
        self.audit_repo
            .create(&AuditLog {
                id: None,
                user_id: *user_id,
                organization_id: None,
                action: AuditAction::VaultItemCreate,
                resource_type: Some("vault_item".to_string()),
                resource_id: Some(item_id),
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                metadata: serde_json::json!({}),
                timestamp: now,
            })
            .await?;

        let mut created_item = item;
        created_item.id = Some(item_id);
        Ok(VaultItemResponse::from(created_item))
    }

    /// Get a single vault item.
    pub async fn get_item(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<VaultItemResponse, AppError> {
        let item = self
            .vault_repo
            .find_by_id(item_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Vault item not found".to_string()))?;

        // Audit read access
        self.audit_repo
            .create(&AuditLog {
                id: None,
                user_id: *user_id,
                organization_id: None,
                action: AuditAction::VaultItemRead,
                resource_type: Some("vault_item".to_string()),
                resource_id: Some(*item_id),
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                metadata: serde_json::json!({}),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(VaultItemResponse::from(item))
    }

    /// List all vault items for a user (non-deleted).
    pub async fn list_items(
        &self,
        user_id: &ObjectId,
        skip: u64,
        limit: i64,
    ) -> Result<(Vec<VaultItemResponse>, u64), AppError> {
        let items = self.vault_repo.find_all_by_user(user_id, skip, limit).await?;
        let total = self.vault_repo.count_by_user(user_id).await?;

        let responses: Vec<VaultItemResponse> = items.into_iter().map(VaultItemResponse::from).collect();
        Ok((responses, total))
    }

    /// Update a vault item.
    pub async fn update_item(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
        req: UpdateVaultItemRequest,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<VaultItemResponse, AppError> {
        // Verify item exists
        self.vault_repo
            .find_by_id(item_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Vault item not found".to_string()))?;

        let mut update_doc = mongodb::bson::Document::new();

        if let Some(item_type) = &req.item_type {
            update_doc.insert(
                "item_type",
                mongodb::bson::to_bson(item_type)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
            );
        }
        if let Some(name) = &req.name_encrypted {
            update_doc.insert("name_encrypted", name.as_str());
        }
        if let Some(data) = &req.data_encrypted {
            update_doc.insert("data_encrypted", data.as_str());
        }
        if let Some(nonce) = &req.nonce {
            update_doc.insert("nonce", nonce.as_str());
        }
        if let Some(folder_id) = &req.folder_id {
            update_doc.insert("folder_id", validate_object_id(folder_id)?);
        }
        if let Some(fav) = req.favorite {
            update_doc.insert("favorite", fav);
        }
        if let Some(reprompt) = req.reprompt {
            update_doc.insert("reprompt", reprompt);
        }
        if let Some(tags) = &req.tags {
            update_doc.insert(
                "tags",
                mongodb::bson::to_bson(tags)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
            );
        }

        self.vault_repo.update(item_id, user_id, update_doc).await?;

        // Audit
        self.audit_repo
            .create(&AuditLog {
                id: None,
                user_id: *user_id,
                organization_id: None,
                action: AuditAction::VaultItemUpdate,
                resource_type: Some("vault_item".to_string()),
                resource_id: Some(*item_id),
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                metadata: serde_json::json!({}),
                timestamp: Utc::now(),
            })
            .await?;

        // Return updated item
        let updated = self
            .vault_repo
            .find_by_id(item_id, user_id)
            .await?
            .ok_or_else(|| AppError::Internal("Failed to fetch updated item".to_string()))?;

        Ok(VaultItemResponse::from(updated))
    }

    /// Soft delete a vault item (move to trash).
    pub async fn soft_delete_item(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<(), AppError> {
        let deleted = self.vault_repo.soft_delete(item_id, user_id).await?;
        if !deleted {
            return Err(AppError::NotFound("Vault item not found".to_string()));
        }

        self.audit_repo
            .create(&AuditLog {
                id: None,
                user_id: *user_id,
                organization_id: None,
                action: AuditAction::VaultItemDelete,
                resource_type: Some("vault_item".to_string()),
                resource_id: Some(*item_id),
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                metadata: serde_json::json!({ "type": "soft_delete" }),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(())
    }

    /// Restore a vault item from trash.
    pub async fn restore_item(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
    ) -> Result<(), AppError> {
        let restored = self.vault_repo.restore(item_id, user_id).await?;
        if !restored {
            return Err(AppError::NotFound(
                "Vault item not found in trash".to_string(),
            ));
        }
        Ok(())
    }

    /// Permanently delete a vault item.
    pub async fn permanent_delete_item(
        &self,
        item_id: &ObjectId,
        user_id: &ObjectId,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<(), AppError> {
        let deleted = self.vault_repo.permanent_delete(item_id, user_id).await?;
        if !deleted {
            return Err(AppError::NotFound("Vault item not found".to_string()));
        }

        self.audit_repo
            .create(&AuditLog {
                id: None,
                user_id: *user_id,
                organization_id: None,
                action: AuditAction::VaultItemDelete,
                resource_type: Some("vault_item".to_string()),
                resource_id: Some(*item_id),
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
                metadata: serde_json::json!({ "type": "permanent_delete" }),
                timestamp: Utc::now(),
            })
            .await?;

        Ok(())
    }

    /// List trashed vault items.
    pub async fn list_trash(
        &self,
        user_id: &ObjectId,
    ) -> Result<Vec<VaultItemResponse>, AppError> {
        let items = self.vault_repo.find_trashed(user_id).await?;
        Ok(items.into_iter().map(VaultItemResponse::from).collect())
    }
}
