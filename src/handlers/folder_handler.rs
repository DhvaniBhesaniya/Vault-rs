use axum::{
    extract::{Path, State},
    Json,
};

use crate::dto::common_dto::{success_response, ApiResponse, MessageResponse};
use crate::dto::folder_dto::*;
use crate::errors::AppError;
use crate::middleware::auth::AuthUser;
use crate::services::folder_service::FolderService;
use crate::utils::validation::{validate_object_id, validate_request};

/// GET /api/v1/vault/folders
pub async fn list_folders(
    State(folder_service): State<FolderService>,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
) -> Result<Json<ApiResponse<Vec<FolderResponse>>>, AppError> {
    let folders = folder_service.list_folders(&auth_user.user_id).await?;
    Ok(Json(success_response(folders, None)))
}

/// POST /api/v1/vault/folders
pub async fn create_folder(
    State(folder_service): State<FolderService>,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Json(req): Json<CreateFolderRequest>,
) -> Result<Json<ApiResponse<FolderResponse>>, AppError> {
    validate_request(&req)?;

    let response = folder_service
        .create_folder(&auth_user.user_id, req)
        .await?;

    Ok(Json(success_response(response, None)))
}

/// PUT /api/v1/vault/folders/:id
pub async fn update_folder(
    State(folder_service): State<FolderService>,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(folder_id): Path<String>,
    Json(req): Json<UpdateFolderRequest>,
) -> Result<Json<ApiResponse<MessageResponse>>, AppError> {
    validate_request(&req)?;
    let folder_oid = validate_object_id(&folder_id)?;

    folder_service
        .update_folder(&folder_oid, &auth_user.user_id, req)
        .await?;

    Ok(Json(success_response(
        MessageResponse {
            message: "Folder updated".to_string(),
        },
        None,
    )))
}

/// DELETE /api/v1/vault/folders/:id
pub async fn delete_folder(
    State(folder_service): State<FolderService>,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(folder_id): Path<String>,
) -> Result<Json<ApiResponse<MessageResponse>>, AppError> {
    let folder_oid = validate_object_id(&folder_id)?;

    folder_service
        .delete_folder(&folder_oid, &auth_user.user_id)
        .await?;

    Ok(Json(success_response(
        MessageResponse {
            message: "Folder deleted".to_string(),
        },
        None,
    )))
}
