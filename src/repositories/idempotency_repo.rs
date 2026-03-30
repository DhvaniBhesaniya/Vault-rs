use mongodb::{
    bson::{doc, oid::ObjectId},
    Collection, Database, IndexModel,
};
use sha2::{Digest, Sha256};

use crate::errors::AppError;
use crate::models::idempotency::IdempotencyKey;

/// Data access layer for the `idempotency_keys` collection.
#[derive(Clone)]
pub struct IdempotencyRepository {
    collection: Collection<IdempotencyKey>,
}

impl IdempotencyRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection::<IdempotencyKey>("idempotency_keys"),
        }
    }

    /// Compute the key hash from user_id + idempotency_key + endpoint.
    pub fn compute_key_hash(user_id: &ObjectId, idempotency_key: &str, endpoint: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(user_id.to_hex().as_bytes());
        hasher.update(idempotency_key.as_bytes());
        hasher.update(endpoint.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Check if an idempotency key already exists.
    pub async fn find_by_key_hash(
        &self,
        key_hash: &str,
        user_id: &ObjectId,
    ) -> Result<Option<IdempotencyKey>, AppError> {
        let record = self
            .collection
            .find_one(doc! { "key_hash": key_hash, "user_id": user_id })
            .await?;
        Ok(record)
    }

    /// Store a new idempotency key with its response.
    pub async fn create(&self, record: &IdempotencyKey) -> Result<(), AppError> {
        self.collection.insert_one(record).await?;
        Ok(())
    }

    /// Ensure indexes on the idempotency_keys collection.
    pub async fn ensure_indexes(&self) -> Result<(), AppError> {
        let indexes = vec![
            IndexModel::builder()
                .keys(doc! { "key_hash": 1, "user_id": 1 })
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
