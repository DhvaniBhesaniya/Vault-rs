//! Shared test infrastructure for integration tests.
//!
//! Provides `TestApp` — a self-contained test harness that:
//! - Connects to MongoDB and creates a unique database per test
//! - Builds the full Axum router with all middleware
//! - Offers helper methods for HTTP requests and auth flows
//! - Cleans up the test database when done

#![allow(dead_code)]

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    Router,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use http_body_util::BodyExt;
use mongodb::Database;
use serde_json::Value;
use tower::ServiceExt;

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

// ─── Test Constants ─────────────────────────────────────────────────────────

/// Low Argon2 params for fast test execution (client-side KDF).
pub const TEST_KDF_MEMORY_KB: u32 = 1024;
pub const TEST_KDF_ITERATIONS: u32 = 1;
pub const TEST_KDF_PARALLELISM: u32 = 1;

pub const TEST_EMAIL: &str = "testuser@example.com";
pub const TEST_PASSWORD: &str = "SuperSecretP@ssw0rd!";
pub const TEST_NAME: &str = "Test User";

// ─── TestApp ────────────────────────────────────────────────────────────────

/// Self-contained test harness for integration tests.
pub struct TestApp {
    pub app: Router,
    pub db: Database,
    pub db_name: String,
    pub settings: Arc<Settings>,
}

impl TestApp {
    /// Create a new test app with a fresh, isolated MongoDB database.
    ///
    /// # Panics
    /// Panics if MongoDB is not reachable at `mongodb://localhost:27017`.
    pub async fn new() -> Self {
        let db_name = format!("rustvault_test_{}", uuid::Uuid::new_v4().simple());
        let settings = Arc::new(test_settings(&db_name));

        let client = mongodb::Client::with_uri_str(&settings.mongodb_uri)
            .await
            .expect(
                "Failed to connect to MongoDB. Is it running? Try: docker compose up -d",
            );

        let db = client.database(&db_name);

        // Verify connectivity
        db.run_command(mongodb::bson::doc! { "ping": 1 })
            .await
            .expect("MongoDB ping failed. Ensure MongoDB is running on localhost:27017.");

        // Build repositories
        let user_repo = UserRepository::new(&db);
        let session_repo = SessionRepository::new(&db);
        let audit_repo = AuditLogRepository::new(&db);
        let vault_repo = VaultItemRepository::new(&db);
        let folder_repo = FolderRepository::new(&db);

        // Build services
        let auth_service = AuthService::new(
            user_repo.clone(),
            session_repo,
            audit_repo.clone(),
            settings.clone(),
        );
        let vault_service = VaultService::new(vault_repo, audit_repo);
        let folder_service = FolderService::new(folder_repo);

        let state = AppState {
            auth_service,
            vault_service,
            folder_service,
            db: db.clone(),
            settings: settings.clone(),
        };

        let app = routes::build_router(state, settings.clone(), user_repo);

        Self {
            app,
            db,
            db_name,
            settings,
        }
    }

    /// Send an HTTP request through the app router (clones the router for each call).
    pub async fn request(&self, req: Request<Body>) -> Response<Body> {
        self.app.clone().oneshot(req).await.unwrap()
    }

    /// Send a GET request.
    pub async fn get(&self, uri: &str) -> Response<Body> {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        self.request(req).await
    }

    /// Send a GET request with an Authorization bearer token.
    pub async fn get_auth(&self, uri: &str, token: &str) -> Response<Body> {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        self.request(req).await
    }

    /// Send a POST request with a JSON body.
    pub async fn post_json(&self, uri: &str, body: &Value) -> Response<Body> {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(body).unwrap()))
            .unwrap();
        self.request(req).await
    }

    /// Send a POST request with JSON body and Authorization token.
    pub async fn post_json_auth(&self, uri: &str, body: &Value, token: &str) -> Response<Body> {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::from(serde_json::to_string(body).unwrap()))
            .unwrap();
        self.request(req).await
    }

    /// Send a PUT request with JSON body and Authorization token.
    pub async fn put_json_auth(&self, uri: &str, body: &Value, token: &str) -> Response<Body> {
        let req = Request::builder()
            .method("PUT")
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::from(serde_json::to_string(body).unwrap()))
            .unwrap();
        self.request(req).await
    }

    /// Send a DELETE request with Authorization token.
    pub async fn delete_auth(&self, uri: &str, token: &str) -> Response<Body> {
        let req = Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        self.request(req).await
    }

    /// Register a test user and return the parsed JSON response.
    pub async fn register_user(
        &self,
        email: &str,
        password: &str,
        name: &str,
    ) -> (StatusCode, Value) {
        let body = make_register_body(email, password, name);
        let resp = self.post_json("/api/v1/auth/register", &body).await;
        let status = resp.status();
        let json = body_json(resp).await;
        (status, json)
    }

    /// Register the default test user.
    pub async fn register_default_user(&self) -> (StatusCode, Value) {
        self.register_user(TEST_EMAIL, TEST_PASSWORD, TEST_NAME)
            .await
    }

    /// Login a user and return (status, json, access_token, refresh_token).
    pub async fn login_user(
        &self,
        email: &str,
        password: &str,
    ) -> (StatusCode, Value, Option<String>, Option<String>) {
        let body = make_login_body(email, password);
        let resp = self.post_json("/api/v1/auth/login", &body).await;
        let status = resp.status();
        let json = body_json(resp).await;

        let access_token = json["data"]["access_token"].as_str().map(String::from);
        let refresh_token = json["data"]["refresh_token"].as_str().map(String::from);

        (status, json, access_token, refresh_token)
    }

    /// Login the default test user.
    pub async fn login_default_user(&self) -> (StatusCode, Value, Option<String>, Option<String>) {
        self.login_user(TEST_EMAIL, TEST_PASSWORD).await
    }

    /// Register + login the default test user. Returns (access_token, refresh_token).
    pub async fn register_and_login(&self) -> (String, String) {
        let (status, _) = self.register_default_user().await;
        assert_eq!(status, StatusCode::OK, "Registration should succeed");

        let (status, _, access_token, refresh_token) = self.login_default_user().await;
        assert_eq!(status, StatusCode::OK, "Login should succeed");

        (access_token.unwrap(), refresh_token.unwrap())
    }

    /// Drop the test database (cleanup).
    pub async fn cleanup(&self) {
        self.db.drop().await.ok();
    }
}

// ─── Crypto Helpers ─────────────────────────────────────────────────────────

/// Compute the master_password_hash for auth (base64-encoded).
///
/// This mirrors client-side crypto:
/// 1. Argon2id(password, email) → master_key
/// 2. HKDF(master_key, password) → auth_hash
/// 3. base64(auth_hash) → master_password_hash
pub fn compute_master_password_hash(email: &str, password: &str) -> String {
    let master_key = vault_rs::crypto::argon2::derive_master_key(
        password.as_bytes(),
        email,
        TEST_KDF_MEMORY_KB,
        TEST_KDF_ITERATIONS,
        TEST_KDF_PARALLELISM,
    )
    .expect("Failed to derive master key");

    let auth_hash = vault_rs::crypto::hkdf::derive_master_password_hash(
        &master_key,
        password.as_bytes(),
    )
    .expect("Failed to derive master password hash");

    BASE64.encode(auth_hash)
}

// ─── Request Body Builders ──────────────────────────────────────────────────

/// Build a registration request JSON body.
pub fn make_register_body(email: &str, password: &str, name: &str) -> Value {
    let master_pw_hash = compute_master_password_hash(email, password);

    // Generate realistic-looking encrypted keys (server stores but doesn't process them)
    let fake_encrypted_key = BASE64.encode(b"test_protected_symmetric_key_data_padding!");
    let fake_nonce = BASE64.encode(b"test_nonce12"); // 12 bytes

    serde_json::json!({
        "email": email,
        "name": name,
        "master_password_hash": master_pw_hash,
        "protected_symmetric_key": fake_encrypted_key,
        "protected_symmetric_key_nonce": fake_nonce,
        "kdf_memory_kb": TEST_KDF_MEMORY_KB,
        "kdf_iterations": TEST_KDF_ITERATIONS,
        "kdf_parallelism": TEST_KDF_PARALLELISM
    })
}

/// Build a login request JSON body.
pub fn make_login_body(email: &str, password: &str) -> Value {
    let master_pw_hash = compute_master_password_hash(email, password);

    serde_json::json!({
        "email": email,
        "master_password_hash": master_pw_hash,
        "device_name": "Integration Test"
    })
}

/// Build a create vault item request body.
pub fn make_vault_item_body(item_type: &str, name: &str) -> Value {
    serde_json::json!({
        "item_type": item_type,
        "name_encrypted": BASE64.encode(name.as_bytes()),
        "data_encrypted": BASE64.encode(b"encrypted_login_data_placeholder_content"),
        "nonce": BASE64.encode(b"random_nonce"),
        "favorite": false,
        "reprompt": false,
        "tags": ["test"]
    })
}

/// Build a create folder request body.
pub fn make_folder_body(name: &str) -> Value {
    serde_json::json!({
        "name_encrypted": BASE64.encode(name.as_bytes())
    })
}

// ─── Response Helpers ───────────────────────────────────────────────────────

/// Read the response body and parse it as JSON.
pub async fn body_json(response: Response<Body>) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect response body")
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        let text = String::from_utf8_lossy(&bytes);
        panic!("Failed to parse response body as JSON: {}", text);
    })
}

/// Assert response status and return parsed JSON body.
pub async fn assert_status_and_json(response: Response<Body>, expected: StatusCode) -> Value {
    let status = response.status();
    let json = body_json(response).await;
    assert_eq!(
        status, expected,
        "Expected status {}, got {}. Body: {}",
        expected, status, json
    );
    json
}

// ─── Settings ───────────────────────────────────────────────────────────────

/// Build test-friendly settings with low crypto params for speed.
fn test_settings(db_name: &str) -> Settings {
    Settings {
        host: "127.0.0.1".to_string(),
        port: 0, // Not binding to a real port in tests
        mongodb_uri: std::env::var("TEST_MONGODB_URI")
            .unwrap_or_else(|_| "mongodb://localhost:27017".to_string()),
        database_name: db_name.to_string(),
        jwt_secret: "test_jwt_secret_key_for_integration_tests_only_12345".to_string(),
        jwt_access_token_expiry_secs: 900,       // 15 min
        jwt_refresh_token_expiry_secs: 604800,    // 7 days
        argon2_memory_kb: TEST_KDF_MEMORY_KB,     // Low for speed
        argon2_iterations: TEST_KDF_ITERATIONS,
        argon2_parallelism: TEST_KDF_PARALLELISM,
        rate_limit_auth_max: 100,
        rate_limit_auth_window_secs: 60,
        rate_limit_write_max: 100,
        rate_limit_write_window_secs: 60,
        rate_limit_read_max: 200,
        rate_limit_read_window_secs: 60,
        max_failed_login_attempts: 5,
        lockout_duration_secs: 3600,
    }
}
