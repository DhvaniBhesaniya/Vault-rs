use mongodb::{bson::doc, Collection, Database};

use crate::errors::AppError;
use crate::models::user::User;

/// Data access layer for the `users` collection.
#[derive(Clone)]
pub struct UserRepository {
    collection: Collection<User>,
}

impl UserRepository {
    pub fn new(db: &Database) -> Self {
        Self {
            collection: db.collection::<User>("users"),
        }
    }

    /// Create a new user. Returns the inserted user ID.
    pub async fn create(&self, user: &User) -> Result<String, AppError> {
        let result = self.collection.insert_one(user).await?;
        Ok(result
            .inserted_id
            .as_object_id()
            .map(|id| id.to_hex())
            .unwrap_or_default())
    }

    /// Find a user by email address.
    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let user = self
            .collection
            .find_one(doc! { "email": email.to_lowercase() })
            .await?;
        Ok(user)
    }

    /// Find a user by their ObjectId.
    pub async fn find_by_id(&self, id: &mongodb::bson::oid::ObjectId) -> Result<Option<User>, AppError> {
        let user = self
            .collection
            .find_one(doc! { "_id": id })
            .await?;
        Ok(user)
    }

    /// Update the failed login attempts counter and optionally lock the account.
    pub async fn increment_failed_logins(
        &self,
        user_id: &mongodb::bson::oid::ObjectId,
        locked_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AppError> {
        let mut update = doc! {
            "$inc": { "failed_login_attempts": 1 },
            "$set": { "updated_at": chrono::Utc::now().to_rfc3339() }
        };

        if let Some(lock_time) = locked_until {
            update
                .get_document_mut("$set")
                .unwrap()
                .insert("locked_until", lock_time.to_rfc3339());
            update
                .get_document_mut("$set")
                .unwrap()
                .insert("account_status", "locked");
        }

        self.collection
            .update_one(doc! { "_id": user_id }, update)
            .await?;
        Ok(())
    }

    /// Reset failed login attempts on successful login.
    pub async fn reset_failed_logins(
        &self,
        user_id: &mongodb::bson::oid::ObjectId,
    ) -> Result<(), AppError> {
        self.collection
            .update_one(
                doc! { "_id": user_id },
                doc! {
                    "$set": {
                        "failed_login_attempts": 0,
                        "locked_until": null,
                        "account_status": "active",
                        "updated_at": chrono::Utc::now().to_rfc3339()
                    }
                },
            )
            .await?;
        Ok(())
    }

    /// Update the master password hash and re-encrypted keys.
    pub async fn update_password(
        &self,
        user_id: &mongodb::bson::oid::ObjectId,
        new_hash: &str,
        new_protected_symmetric_key: &str,
        new_protected_symmetric_key_nonce: &str,
        new_security_stamp: &str,
    ) -> Result<(), AppError> {
        self.collection
            .update_one(
                doc! { "_id": user_id },
                doc! {
                    "$set": {
                        "master_password_hash": new_hash,
                        "protected_symmetric_key": new_protected_symmetric_key,
                        "protected_symmetric_key_nonce": new_protected_symmetric_key_nonce,
                        "security_stamp": new_security_stamp,
                        "updated_at": chrono::Utc::now().to_rfc3339()
                    }
                },
            )
            .await?;
        Ok(())
    }

    /// Ensure indexes exist on the users collection.
    pub async fn ensure_indexes(&self) -> Result<(), AppError> {
        use mongodb::IndexModel;
        use mongodb::bson::doc;

        let indexes = vec![
            IndexModel::builder()
                .keys(doc! { "email": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(true)
                        .build(),
                )
                .build(),
            IndexModel::builder()
                .keys(doc! { "security_stamp": 1 })
                .build(),
        ];

        self.collection.create_indexes(indexes).await?;
        Ok(())
    }
}
