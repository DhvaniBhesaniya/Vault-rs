use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};

use crate::dto::common_dto::{
    paginated_response, success_response, ApiResponse, MessageResponse, PaginationParams,
};
use crate::dto::vault_dto::*;
use crate::errors::AppError;
use crate::middleware::auth::AuthUser;
use crate::services::vault_service::VaultService;
use crate::utils::validation::{validate_object_id, validate_request};

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

/// POST /api/v1/vault/items
pub async fn create_vault_item(
    State(vault_service): State<VaultService>,
    headers: HeaderMap,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Json(req): Json<CreateVaultItemRequest>,
) -> Result<Json<ApiResponse<VaultItemResponse>>, AppError> {
    validate_request(&req)?;

    let ip = extract_ip(&headers);
    let ua = extract_user_agent(&headers);

    let response = vault_service
        .create_item(&auth_user.user_id, req, &ip, ua.as_deref())
        .await?;

    Ok(Json(success_response(response, None)))
}

/// GET /api/v1/vault/items
pub async fn list_vault_items(
    State(vault_service): State<VaultService>,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ApiResponse<Vec<VaultItemResponse>>>, AppError> {
    let (items, total) = vault_service
        .list_items(&auth_user.user_id, params.skip(), params.per_page() as i64)
        .await?;

    Ok(Json(paginated_response(
        items,
        None,
        params.page(),
        params.per_page(),
        total,
    )))
}

/// GET /api/v1/vault/items/:id
pub async fn get_vault_item(
    State(vault_service): State<VaultService>,
    headers: HeaderMap,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(item_id): Path<String>,
) -> Result<Json<ApiResponse<VaultItemResponse>>, AppError> {
    let item_oid = validate_object_id(&item_id)?;
    let ip = extract_ip(&headers);
    let ua = extract_user_agent(&headers);

    let response = vault_service
        .get_item(&item_oid, &auth_user.user_id, &ip, ua.as_deref())
        .await?;

    Ok(Json(success_response(response, None)))
}

/// PUT /api/v1/vault/items/:id
pub async fn update_vault_item(
    State(vault_service): State<VaultService>,
    headers: HeaderMap,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(item_id): Path<String>,
    Json(req): Json<UpdateVaultItemRequest>,
) -> Result<Json<ApiResponse<VaultItemResponse>>, AppError> {
    let item_oid = validate_object_id(&item_id)?;
    let ip = extract_ip(&headers);
    let ua = extract_user_agent(&headers);

    let response = vault_service
        .update_item(&item_oid, &auth_user.user_id, req, &ip, ua.as_deref())
        .await?;

    Ok(Json(success_response(response, None)))
}

/// DELETE /api/v1/vault/items/:id
pub async fn soft_delete_vault_item(
    State(vault_service): State<VaultService>,
    headers: HeaderMap,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(item_id): Path<String>,
) -> Result<Json<ApiResponse<MessageResponse>>, AppError> {
    let item_oid = validate_object_id(&item_id)?;
    let ip = extract_ip(&headers);
    let ua = extract_user_agent(&headers);

    vault_service
        .soft_delete_item(&item_oid, &auth_user.user_id, &ip, ua.as_deref())
        .await?;

    Ok(Json(success_response(
        MessageResponse {
            message: "Item moved to trash".to_string(),
        },
        None,
    )))
}

/// POST /api/v1/vault/items/:id/restore
pub async fn restore_vault_item(
    State(vault_service): State<VaultService>,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(item_id): Path<String>,
) -> Result<Json<ApiResponse<MessageResponse>>, AppError> {
    let item_oid = validate_object_id(&item_id)?;

    vault_service
        .restore_item(&item_oid, &auth_user.user_id)
        .await?;

    Ok(Json(success_response(
        MessageResponse {
            message: "Item restored from trash".to_string(),
        },
        None,
    )))
}

/// DELETE /api/v1/vault/items/:id/permanent
pub async fn permanent_delete_vault_item(
    State(vault_service): State<VaultService>,
    headers: HeaderMap,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(item_id): Path<String>,
) -> Result<Json<ApiResponse<MessageResponse>>, AppError> {
    let item_oid = validate_object_id(&item_id)?;
    let ip = extract_ip(&headers);
    let ua = extract_user_agent(&headers);

    vault_service
        .permanent_delete_item(&item_oid, &auth_user.user_id, &ip, ua.as_deref())
        .await?;

    Ok(Json(success_response(
        MessageResponse {
            message: "Item permanently deleted".to_string(),
        },
        None,
    )))
}

/// GET /api/v1/vault/items/trash
pub async fn list_trash(
    State(vault_service): State<VaultService>,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
) -> Result<Json<ApiResponse<Vec<VaultItemResponse>>>, AppError> {
    let items = vault_service.list_trash(&auth_user.user_id).await?;
    Ok(Json(success_response(items, None)))
}
