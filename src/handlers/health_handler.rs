use axum::Json;

use crate::dto::common_dto::{success_response, ApiResponse};
use crate::errors::AppError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// GET /api/v1/health
pub async fn health_check() -> Result<Json<ApiResponse<HealthResponse>>, AppError> {
    Ok(Json(success_response(
        HealthResponse {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        None,
    )))
}

/// GET /api/v1/health/ready
pub async fn readiness_check(
    axum::extract::State(db): axum::extract::State<mongodb::Database>,
) -> Result<Json<ApiResponse<HealthResponse>>, AppError> {
    // Ping MongoDB to check connectivity
    db.run_command(mongodb::bson::doc! { "ping": 1 })
        .await
        .map_err(|e| AppError::Internal(format!("Database not ready: {}", e)))?;

    Ok(Json(success_response(
        HealthResponse {
            status: "ready".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        None,
    )))
}
