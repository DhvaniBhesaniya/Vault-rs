use chrono::Utc;
use mongodb::{
    bson::{doc, oid::ObjectId},
    Collection, Database, IndexModel,
};
use futures::TryStreamExt;

use crate::errors::AppError;
use crate::models::session::Session;

/// Data access layer for the `sessions` collection.
#[derive(Clone)]
pub struct SessionRepository {
    collection: Collection<Session>,
}

impl SessionRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection::<Session>("sessions"),
        }
    }

    pub async fn create(&self, session: &Session) -> Result<String, AppError> {
        let result = self.collection.insert_one(session).await?;
        Ok(result
            .inserted_id
            .as_object_id()
            .map(|id| id.to_hex())
            .unwrap_or_default())
    }

    /// Find a session by refresh token hash (for token refresh).
    pub async fn find_by_refresh_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Session>, AppError> {
        let session = self
            .collection
            .find_one(doc! {
                "refresh_token_hash": token_hash,
                "revoked": false,
            })
            .await?;
        Ok(session)
    }

    /// List all active sessions for a user.
    pub async fn find_all_by_user(&self, user_id: &ObjectId) -> Result<Vec<Session>, AppError> {
        let cursor = self
            .collection
            .find(doc! {
                "user_id": user_id,
                "revoked": false,
                "expires_at": { "$gt": Utc::now().to_rfc3339() }
            })
            .await?;

        let sessions: Vec<Session> = cursor.try_collect().await?;
        Ok(sessions)
    }

    /// Revoke a specific session.
    pub async fn revoke(&self, session_id: &ObjectId) -> Result<bool, AppError> {
        let result = self
            .collection
            .update_one(
                doc! { "_id": session_id },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        Ok(result.modified_count > 0)
    }

    /// Revoke all sessions for a user.
    pub async fn revoke_all_for_user(&self, user_id: &ObjectId) -> Result<u64, AppError> {
        let result = self
            .collection
            .update_many(
                doc! { "user_id": user_id, "revoked": false },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        Ok(result.modified_count)
    }

    /// Update the last_used_at timestamp for a session.
    pub async fn touch(&self, session_id: &ObjectId) -> Result<(), AppError> {
        self.collection
            .update_one(
                doc! { "_id": session_id },
                doc! { "$set": { "last_used_at": Utc::now().to_rfc3339() } },
            )
            .await?;
        Ok(())
    }

    /// Ensure indexes on the sessions collection.
    pub async fn ensure_indexes(&self) -> Result<(), AppError> {
        let indexes = vec![
            IndexModel::builder()
                .keys(doc! { "user_id": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "refresh_token_hash": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(true)
                        .build(),
                )
                .build(),
        ];

        self.collection.create_indexes(indexes).await?;
        Ok(())
    }
}
