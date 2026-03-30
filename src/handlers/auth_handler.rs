use axum::{extract::State, http::HeaderMap, Json};

use crate::dto::auth_dto::*;
use crate::dto::common_dto::{success_response, ApiResponse, MessageResponse};
use crate::errors::AppError;
use crate::middleware::auth::AuthUser;
use crate::services::auth_service::AuthService;
use crate::utils::validation::validate_request;

/// Extract the client IP from headers (supports X-Forwarded-For).
fn extract_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("unknown").trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// POST /api/v1/auth/register
pub async fn register(
    State(auth_service): State<AuthService>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<ApiResponse<RegisterResponse>>, AppError> {
    validate_request(&req)?;

    let ip = extract_ip(&headers);
    let ua = extract_user_agent(&headers);

    let response = auth_service.register(req, &ip, ua.as_deref()).await?;
    Ok(Json(success_response(response, None)))
}

/// POST /api/v1/auth/login
pub async fn login(
    State(auth_service): State<AuthService>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<ApiResponse<LoginResponse>>, AppError> {
    validate_request(&req)?;

    let ip = extract_ip(&headers);
    let ua = extract_user_agent(&headers);

    let response = auth_service.login(req, &ip, ua.as_deref()).await?;
    Ok(Json(success_response(response, None)))
}

/// POST /api/v1/auth/refresh
pub async fn refresh_token(
    State(auth_service): State<AuthService>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<ApiResponse<RefreshTokenResponse>>, AppError> {
    let response = auth_service.refresh_token(&req.refresh_token).await?;
    Ok(Json(success_response(response, None)))
}

/// POST /api/v1/auth/logout
pub async fn logout(
    State(auth_service): State<AuthService>,
    headers: HeaderMap,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<ApiResponse<MessageResponse>>, AppError> {
    let ip = extract_ip(&headers);
    let ua = extract_user_agent(&headers);

    auth_service
        .logout(&req.refresh_token, &auth_user.user_id, &ip, ua.as_deref())
        .await?;

    Ok(Json(success_response(
        MessageResponse {
            message: "Logged out successfully".to_string(),
        },
        None,
    )))
}

/// POST /api/v1/auth/logout-all
pub async fn logout_all(
    State(auth_service): State<AuthService>,
    headers: HeaderMap,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
) -> Result<Json<ApiResponse<MessageResponse>>, AppError> {
    let ip = extract_ip(&headers);
    let ua = extract_user_agent(&headers);

    let count = auth_service
        .logout_all(&auth_user.user_id, &ip, ua.as_deref())
        .await?;

    Ok(Json(success_response(
        MessageResponse {
            message: format!("{} sessions revoked", count),
        },
        None,
    )))
}
