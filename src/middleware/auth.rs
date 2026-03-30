use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use mongodb::bson::oid::ObjectId;

use crate::config::Settings;
use crate::errors::AppError;
use crate::repositories::user_repo::UserRepository;
use crate::utils::jwt;

/// Authenticated user info extracted from JWT and injected into request extensions.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: ObjectId,
    pub email: String,
    pub security_stamp: String,
}

/// JWT authentication middleware.
///
/// Extracts the Bearer token from the Authorization header, validates it,
/// verifies the security stamp against the database, and injects `AuthUser`
/// into the request extensions for downstream handlers.
pub async fn auth_middleware(
    State((settings, user_repo)): State<(Arc<Settings>, UserRepository)>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            AppError::Unauthorized("Invalid Authorization header format".to_string())
        })?;

    let token_data = jwt::validate_token(token, &settings.jwt_secret)?;
    let claims = token_data.claims;

    if claims.token_type != "access" {
        return Err(AppError::Unauthorized("Invalid token type".to_string()));
    }

    let user_id = jwt::extract_user_id(&claims)?;

    // Verify security stamp against database to catch password changes
    let user = user_repo
        .find_by_id(&user_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    if user.security_stamp != claims.security_stamp {
        return Err(AppError::Unauthorized(
            "Session invalidated. Please log in again.".to_string(),
        ));
    }

    // Inject authenticated user into request extensions
    req.extensions_mut().insert(AuthUser {
        user_id,
        email: claims.email,
        security_stamp: claims.security_stamp,
    });

    Ok(next.run(req).await)
}

