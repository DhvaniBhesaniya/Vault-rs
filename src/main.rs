use std::sync::Arc;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use vault_rs::config::Settings;
use vault_rs::repositories::{
    audit_log_repo::AuditLogRepository,
    folder_repo::FolderRepository,
    session_repo::SessionRepository,
    user_repo::UserRepository,
    vault_item_repo::VaultItemRepository,
};
use vault_rs::routes;
use vault_rs::services::{
    auth_service::AuthService,
    folder_service::FolderService,
    vault_service::VaultService,
};
use vault_rs::state::AppState;

#[tokio::main]
async fn main() {
    init_tracing();

    let settings = Arc::new(
        Settings::from_env().expect("Failed to load settings from environment"),
    );

    let db = init_database(&settings).await;
    let app_state = init_services(&db, &settings);
    let user_repo = UserRepository::new(&db);

    let app = routes::build_router(app_state, settings.clone(), user_repo);

    start_server(&settings, app).await;
}

/// Initialize structured logging via tracing.
fn init_tracing() {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vault_rs=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// Connect to MongoDB, verify connectivity, and ensure indexes.
async fn init_database(settings: &Settings) -> mongodb::Database {
    tracing::info!("Connecting to MongoDB at {}", settings.mongodb_uri);

    let client = mongodb::Client::with_uri_str(&settings.mongodb_uri)
        .await
        .expect("Failed to connect to MongoDB");

    let db = client.database(&settings.database_name);

    db.run_command(mongodb::bson::doc! { "ping": 1 })
        .await
        .expect("Failed to ping MongoDB — is it running?");

    tracing::info!("Connected to MongoDB database: {}", settings.database_name);

    ensure_indexes(&db).await;

    db
}

/// Create all MongoDB indexes.
async fn ensure_indexes(db: &mongodb::Database) {
    tracing::info!("Ensuring MongoDB indexes...");

    UserRepository::new(db)
        .ensure_indexes()
        .await
        .expect("Failed to create user indexes");
    SessionRepository::new(db)
        .ensure_indexes()
        .await
        .expect("Failed to create session indexes");
    AuditLogRepository::new(db)
        .ensure_indexes()
        .await
        .expect("Failed to create audit indexes");
    VaultItemRepository::new(db)
        .ensure_indexes()
        .await
        .expect("Failed to create vault indexes");
}

/// Wire up repositories → services → AppState.
fn init_services(db: &mongodb::Database, settings: &Arc<Settings>) -> AppState {
    let user_repo = UserRepository::new(db);
    let session_repo = SessionRepository::new(db);
    let audit_repo = AuditLogRepository::new(db);
    let vault_repo = VaultItemRepository::new(db);
    let folder_repo = FolderRepository::new(db);

    let auth_service = AuthService::new(
        user_repo,
        session_repo,
        audit_repo.clone(),
        settings.clone(),
    );
    let vault_service = VaultService::new(vault_repo, audit_repo);
    let folder_service = FolderService::new(folder_repo);

    AppState {
        auth_service,
        vault_service,
        folder_service,
        db: db.clone(),
        settings: settings.clone(),
    }
}

/// Bind to the configured address and start serving.
async fn start_server(settings: &Settings, app: axum::Router) {
    let addr = settings.server_addr();
    tracing::info!("RustVault server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}
