use std::sync::Arc;

use crate::config::Settings;
use crate::services::{
    auth_service::AuthService,
    folder_service::FolderService,
    vault_service::VaultService,
};

/// Shared application state available to all handlers via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub auth_service: AuthService,
    pub vault_service: VaultService,
    pub folder_service: FolderService,
    pub db: mongodb::Database,
    pub settings: Arc<Settings>,
}

// ─── FromRef implementations so Axum can extract individual pieces from AppState ───

impl axum::extract::FromRef<AppState> for AuthService {
    fn from_ref(state: &AppState) -> Self {
        state.auth_service.clone()
    }
}

impl axum::extract::FromRef<AppState> for VaultService {
    fn from_ref(state: &AppState) -> Self {
        state.vault_service.clone()
    }
}

impl axum::extract::FromRef<AppState> for FolderService {
    fn from_ref(state: &AppState) -> Self {
        state.folder_service.clone()
    }
}

impl axum::extract::FromRef<AppState> for mongodb::Database {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<Settings> {
    fn from_ref(state: &AppState) -> Self {
        state.settings.clone()
    }
}
