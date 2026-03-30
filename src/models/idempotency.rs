use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

/// Idempotency key record to prevent duplicate mutations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyKey {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    /// SHA-256(user_id + idempotency_key + endpoint)
    pub key_hash: String,

    pub user_id: ObjectId,
    pub endpoint: String,
    pub response_status: u16,
    pub response_body: Option<String>,

    pub created_at: DateTime<Utc>,
    /// Auto-expires via MongoDB TTL index (24 hours)
    pub expires_at: DateTime<Utc>,
}
