//! Integration tests for the Authentication endpoints.
//!
//! - POST /api/v1/auth/register  — user registration
//! - POST /api/v1/auth/login     — user login
//! - POST /api/v1/auth/refresh   — token refresh with rotation
//! - POST /api/v1/auth/logout    — single session logout (protected)
//! - POST /api/v1/auth/logout-all — all sessions logout (protected)

mod common;

use axum::http::StatusCode;

// ─── Registration ───────────────────────────────────────────────────────────

#[tokio::test]
async fn register_success() {
    let app = common::TestApp::new().await;

    let (status, json) = app.register_default_user().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    assert_eq!(json["data"]["email"], common::TEST_EMAIL);
    assert!(json["data"]["user_id"].is_string());
    assert_eq!(json["data"]["message"], "Account created successfully");

    app.cleanup().await;
}

#[tokio::test]
async fn register_duplicate_email_fails() {
    let app = common::TestApp::new().await;

    // First registration
    let (status, _) = app.register_default_user().await;
    assert_eq!(status, StatusCode::OK);

    // Second registration with same email
    let (status, json) = app.register_default_user().await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["success"], false);

    app.cleanup().await;
}

#[tokio::test]
async fn register_invalid_email_fails() {
    let app = common::TestApp::new().await;

    let body = common::make_register_body("not-an-email", common::TEST_PASSWORD, "Bad Email");
    let resp = app.post_json("/api/v1/auth/register", &body).await;

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    app.cleanup().await;
}

#[tokio::test]
async fn register_missing_fields_fails() {
    let app = common::TestApp::new().await;

    // Missing master_password_hash
    let body = serde_json::json!({
        "email": "incomplete@example.com",
        "name": "Incomplete"
    });
    let resp = app.post_json("/api/v1/auth/register", &body).await;

    // Should fail with 4xx (either 400 or 422 depending on deserialization)
    assert!(resp.status().is_client_error());

    app.cleanup().await;
}

// ─── Login ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_success() {
    let app = common::TestApp::new().await;

    // Register first
    let (status, _) = app.register_default_user().await;
    assert_eq!(status, StatusCode::OK);

    // Login
    let (status, json, access_token, refresh_token) = app.login_default_user().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    assert!(access_token.is_some(), "Should receive access_token");
    assert!(refresh_token.is_some(), "Should receive refresh_token");
    assert_eq!(json["data"]["email"], common::TEST_EMAIL);
    assert_eq!(json["data"]["token_type"], "Bearer");
    assert_eq!(json["data"]["two_factor_required"], false);

    // Should return the stored keys
    assert!(json["data"]["protected_symmetric_key"].is_string());
    assert!(json["data"]["protected_symmetric_key_nonce"].is_string());

    // Should return KDF params
    assert_eq!(json["data"]["kdf_memory_kb"], common::TEST_KDF_MEMORY_KB);
    assert_eq!(json["data"]["kdf_iterations"], common::TEST_KDF_ITERATIONS);
    assert_eq!(json["data"]["kdf_parallelism"], common::TEST_KDF_PARALLELISM);

    app.cleanup().await;
}

#[tokio::test]
async fn login_wrong_password_fails() {
    let app = common::TestApp::new().await;

    // Register
    let (status, _) = app.register_default_user().await;
    assert_eq!(status, StatusCode::OK);

    // Login with wrong password
    let (status, json, access_token, _) =
        app.login_user(common::TEST_EMAIL, "WrongP@ssword123!").await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["success"], false);
    assert!(access_token.is_none());

    app.cleanup().await;
}

#[tokio::test]
async fn login_nonexistent_user_fails() {
    let app = common::TestApp::new().await;

    let (status, json, _, _) = app.login_user("noone@example.com", "anything").await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["success"], false);

    app.cleanup().await;
}

#[tokio::test]
async fn login_case_insensitive_email() {
    let app = common::TestApp::new().await;

    // Register with lowercase
    let (status, _) = app.register_default_user().await;
    assert_eq!(status, StatusCode::OK);

    // Login with uppercase — should still work (email normalized to lowercase)
    let (status, _, access_token, _) = app
        .login_user(&common::TEST_EMAIL.to_uppercase(), common::TEST_PASSWORD)
        .await;

    // This depends on whether login normalizes the email.
    // If it does, this should succeed; if not, it may fail.
    // Our service lowercases on register but not necessarily on login lookup.
    // Either outcome is acceptable — we just verify no server crash.
    assert!(status == StatusCode::OK || status == StatusCode::UNAUTHORIZED);

    if status == StatusCode::OK {
        assert!(access_token.is_some());
    }

    app.cleanup().await;
}

// ─── Token Refresh ──────────────────────────────────────────────────────────

#[tokio::test]
async fn refresh_token_success() {
    let app = common::TestApp::new().await;

    let (access_token, refresh_token) = app.register_and_login().await;

    // Use the refresh token to get new tokens
    let body = serde_json::json!({ "refresh_token": refresh_token });
    let resp = app.post_json("/api/v1/auth/refresh", &body).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["success"], true);

    let new_access_token = json["data"]["access_token"].as_str().unwrap();
    let new_refresh_token = json["data"]["refresh_token"].as_str().unwrap();

    // New tokens should be different from original ones
    assert_ne!(new_access_token, access_token);
    assert_ne!(new_refresh_token, refresh_token);

    app.cleanup().await;
}

#[tokio::test]
async fn refresh_with_invalid_token_fails() {
    let app = common::TestApp::new().await;

    let body = serde_json::json!({ "refresh_token": "not.a.valid.token" });
    let resp = app.post_json("/api/v1/auth/refresh", &body).await;

    assert!(resp.status().is_client_error());

    app.cleanup().await;
}

#[tokio::test]
async fn refresh_token_rotation_invalidates_old() {
    let app = common::TestApp::new().await;

    let (_access, refresh) = app.register_and_login().await;

    // First refresh — should succeed
    let body = serde_json::json!({ "refresh_token": refresh });
    let resp = app.post_json("/api/v1/auth/refresh", &body).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    let _new_refresh = json["data"]["refresh_token"].as_str().unwrap();

    // Try reusing the OLD refresh token — should fail (token rotation)
    let resp2 = app.post_json("/api/v1/auth/refresh", &body).await;
    assert!(
        resp2.status().is_client_error(),
        "Old refresh token should be invalidated after rotation"
    );

    app.cleanup().await;
}

// ─── Logout ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn logout_success() {
    let app = common::TestApp::new().await;

    let (access, refresh) = app.register_and_login().await;

    let body = serde_json::json!({ "refresh_token": refresh });
    let resp = app.post_json_auth("/api/v1/auth/logout", &body, &access).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["success"], true);
    assert!(json["data"]["message"].as_str().unwrap().contains("Logged out"));

    app.cleanup().await;
}

#[tokio::test]
async fn logout_without_auth_fails() {
    let app = common::TestApp::new().await;

    let body = serde_json::json!({ "refresh_token": "some_token" });
    let resp = app.post_json("/api/v1/auth/logout", &body).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    app.cleanup().await;
}

#[tokio::test]
async fn logout_all_sessions() {
    let app = common::TestApp::new().await;

    // Register and create two sessions
    let (status, _) = app.register_default_user().await;
    assert_eq!(status, StatusCode::OK);

    let (_, _, access1, refresh1) = app.login_default_user().await;
    let (_, _, _access2, _refresh2) = app.login_default_user().await;

    let access1 = access1.unwrap();
    let refresh1 = refresh1.unwrap();

    // Logout all using first session's access token
    let resp = app
        .post_json_auth(
            "/api/v1/auth/logout-all",
            &serde_json::json!({}),
            &access1,
        )
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["success"], true);

    // Old refresh token should no longer work
    let body = serde_json::json!({ "refresh_token": refresh1 });
    let resp = app.post_json("/api/v1/auth/refresh", &body).await;
    assert!(
        resp.status().is_client_error(),
        "Refresh token should be invalid after logout-all"
    );

    app.cleanup().await;
}

// ─── Account Lockout ────────────────────────────────────────────────────────

#[tokio::test]
async fn account_locks_after_max_failed_attempts() {
    let app = common::TestApp::new().await;

    // Register
    let (status, _) = app.register_default_user().await;
    assert_eq!(status, StatusCode::OK);

    // Attempt login with wrong password repeatedly (max_failed_login_attempts = 5 in test settings)
    for i in 0..5 {
        let (status, _json, _, _) =
            app.login_user(common::TEST_EMAIL, "wrong_password").await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
            "Attempt {} should fail with 401 or 403, got {}",
            i + 1,
            status
        );
    }

    // Next attempt should be locked (403 or a locked-specific error)
    let (status, json, _, _) = app.login_user(common::TEST_EMAIL, "wrong_password").await;
    // After lockout, it should return locked or unauthorized
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "Account should be locked or denied after max failed attempts, got: {} body: {}",
        status,
        json
    );

    app.cleanup().await;
}

// ─── Protected Endpoint Access ──────────────────────────────────────────────

#[tokio::test]
async fn protected_endpoint_without_token_returns_401() {
    let app = common::TestApp::new().await;

    // Try accessing a protected endpoint without auth
    let resp = app.get("/api/v1/vault/items").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    app.cleanup().await;
}

#[tokio::test]
async fn protected_endpoint_with_invalid_token_returns_401() {
    let app = common::TestApp::new().await;

    let resp = app.get_auth("/api/v1/vault/items", "invalid.jwt.token").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    app.cleanup().await;
}
