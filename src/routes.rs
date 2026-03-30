use std::sync::Arc;

use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::config::Settings;
use crate::handlers::{auth_handler, folder_handler, health_handler, tools_handler, vault_handler};
use crate::middleware::{auth, request_id, security_headers};
use crate::repositories::user_repo::UserRepository;
use crate::state::AppState;

/// Build the full application router with all routes, middleware, and state.
pub fn build_router(state: AppState, settings: Arc<Settings>, user_repo: UserRepository) -> Router {
    let public_routes = public_routes();
    let protected_routes = protected_routes(settings, user_repo);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB body limit
        .layer(TraceLayer::new_for_http())
        .layer(axum_middleware::from_fn(
            security_headers::security_headers_middleware,
        ))
        .layer(axum_middleware::from_fn(
            request_id::request_id_middleware,
        ))
        .with_state(state)
}

/// Public routes — no authentication required.
fn public_routes() -> Router<AppState> {
    Router::new()
        // Auth
        .route("/api/v1/auth/register", post(auth_handler::register))
        .route("/api/v1/auth/login", post(auth_handler::login))
        .route("/api/v1/auth/refresh", post(auth_handler::refresh_token))
        // Health
        .route("/api/v1/health", get(health_handler::health_check))
        .route("/api/v1/health/ready", get(health_handler::readiness_check))
        // Tools (public)
        .route(
            "/api/v1/tools/generate-password",
            post(tools_handler::generate_password_handler),
        )
        .route(
            "/api/v1/tools/generate-passphrase",
            post(tools_handler::generate_passphrase_handler),
        )
        .route(
            "/api/v1/tools/check-breach",
            post(tools_handler::check_breach_handler),
        )
}

/// Protected routes — JWT authentication middleware applied to all.
fn protected_routes(settings: Arc<Settings>, user_repo: UserRepository) -> Router<AppState> {
    Router::new()
        // Auth (authenticated)
        .route("/api/v1/auth/logout", post(auth_handler::logout))
        .route("/api/v1/auth/logout-all", post(auth_handler::logout_all))
        // Vault items
        .route("/api/v1/vault/items", get(vault_handler::list_vault_items))
        .route(
            "/api/v1/vault/items",
            post(vault_handler::create_vault_item),
        )
        .route("/api/v1/vault/items/trash", get(vault_handler::list_trash))
        .route(
            "/api/v1/vault/items/{id}",
            get(vault_handler::get_vault_item),
        )
        .route(
            "/api/v1/vault/items/{id}",
            put(vault_handler::update_vault_item),
        )
        .route(
            "/api/v1/vault/items/{id}",
            delete(vault_handler::soft_delete_vault_item),
        )
        .route(
            "/api/v1/vault/items/{id}/restore",
            post(vault_handler::restore_vault_item),
        )
        .route(
            "/api/v1/vault/items/{id}/permanent",
            delete(vault_handler::permanent_delete_vault_item),
        )
        // Folders
        .route("/api/v1/vault/folders", get(folder_handler::list_folders))
        .route(
            "/api/v1/vault/folders",
            post(folder_handler::create_folder),
        )
        .route(
            "/api/v1/vault/folders/{id}",
            put(folder_handler::update_folder),
        )
        .route(
            "/api/v1/vault/folders/{id}",
            delete(folder_handler::delete_folder),
        )
        // Apply JWT auth middleware to all routes in this group
        .layer(axum_middleware::from_fn_with_state(
            (settings, user_repo),
            auth::auth_middleware,
        ))
}
