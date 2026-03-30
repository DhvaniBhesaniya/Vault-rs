use mongodb::bson::oid::ObjectId;

use crate::errors::AppError;
use crate::models::audit_log::AuditLog;
use crate::repositories::audit_log_repo::AuditLogRepository;

/// Audit service for querying audit logs.
#[derive(Clone)]
pub struct AuditService {
    pub audit_repo: AuditLogRepository,
}

impl AuditService {
    pub fn new(audit_repo: AuditLogRepository) -> Self {
        Self { audit_repo }
    }

    pub async fn get_user_logs(
        &self,
        user_id: &ObjectId,
        skip: u64,
        limit: i64,
    ) -> Result<(Vec<AuditLog>, u64), AppError> {
        let logs = self.audit_repo.find_by_user(user_id, skip, limit).await?;
        let total = self.audit_repo.count_by_user(user_id).await?;
        Ok((logs, total))
    }
}
