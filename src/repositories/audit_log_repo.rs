use mongodb::{
    bson::{doc, oid::ObjectId},
    Collection, Database, IndexModel,
};
use futures::TryStreamExt;

use crate::errors::AppError;
use crate::models::audit_log::AuditLog;

/// Data access layer for the `audit_logs` collection.
#[derive(Clone)]
pub struct AuditLogRepository {
    collection: Collection<AuditLog>,
}

impl AuditLogRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection::<AuditLog>("audit_logs"),
        }
    }

    /// Insert an audit log entry.
    pub async fn create(&self, log: &AuditLog) -> Result<(), AppError> {
        self.collection.insert_one(log).await?;
        Ok(())
    }

    /// Query audit logs for a user, sorted by latest first.
    pub async fn find_by_user(
        &self,
        user_id: &ObjectId,
        skip: u64,
        limit: i64,
    ) -> Result<Vec<AuditLog>, AppError> {
        let cursor = self
            .collection
            .find(doc! { "user_id": user_id })
            .sort(doc! { "timestamp": -1 })
            .skip(skip)
            .limit(limit)
            .await?;

        let logs: Vec<AuditLog> = cursor.try_collect().await?;
        Ok(logs)
    }

    /// Count audit logs for a user.
    pub async fn count_by_user(&self, user_id: &ObjectId) -> Result<u64, AppError> {
        let count = self
            .collection
            .count_documents(doc! { "user_id": user_id })
            .await?;
        Ok(count)
    }

    /// Ensure indexes on the audit_logs collection.
    pub async fn ensure_indexes(&self) -> Result<(), AppError> {
        let indexes = vec![
            IndexModel::builder()
                .keys(doc! { "user_id": 1, "timestamp": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "organization_id": 1, "timestamp": -1 })
                .build(),
        ];

        self.collection.create_indexes(indexes).await?;
        Ok(())
    }
}
