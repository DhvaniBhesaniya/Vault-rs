//! Integration tests for the Folder endpoints.
//!
//! - POST   /api/v1/vault/folders        — create folder
//! - GET    /api/v1/vault/folders        — list folders
//! - PUT    /api/v1/vault/folders/{id}   — update folder
//! - DELETE /api/v1/vault/folders/{id}   — delete folder

mod common;

use axum::http::StatusCode;
use base64::Engine;

// ─── Create ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_folder_success() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    let body = common::make_folder_body("Personal");
    let resp = app
        .post_json_auth("/api/v1/vault/folders", &body, &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["success"], true);
    assert!(json["data"]["id"].is_string());
    assert!(json["data"]["name_encrypted"].is_string());

    app.cleanup().await;
}

#[tokio::test]
async fn create_folder_without_auth_fails() {
    let app = common::TestApp::new().await;

    let body = common::make_folder_body("Unauthorized");
    let resp = app.post_json("/api/v1/vault/folders", &body).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    app.cleanup().await;
}

#[tokio::test]
async fn create_subfolder() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create parent folder
    let parent_body = common::make_folder_body("Parent");
    let resp = app
        .post_json_auth("/api/v1/vault/folders", &parent_body, &token)
        .await;
    let parent_json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let parent_id = parent_json["data"]["id"].as_str().unwrap();

    // Create child folder
    let child_body = serde_json::json!({
        "name_encrypted": base64::engine::general_purpose::STANDARD.encode(b"Child"),
        "parent_folder_id": parent_id
    });
    let resp = app
        .post_json_auth("/api/v1/vault/folders", &child_body, &token)
        .await;
    let child_json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(child_json["data"]["parent_folder_id"], parent_id);

    app.cleanup().await;
}

// ─── List ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_folders_empty() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    let resp = app.get_auth("/api/v1/vault/folders", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["success"], true);
    assert!(json["data"].is_array());
    assert_eq!(json["data"].as_array().unwrap().len(), 0);

    app.cleanup().await;
}

#[tokio::test]
async fn list_folders_returns_all() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create 3 folders
    let names = ["Personal", "Work", "Finance"];
    for name in names {
        let body = common::make_folder_body(name);
        app.post_json_auth("/api/v1/vault/folders", &body, &token)
            .await;
    }

    let resp = app.get_auth("/api/v1/vault/folders", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    let folders = json["data"].as_array().unwrap();
    assert_eq!(folders.len(), 3);

    app.cleanup().await;
}

// ─── Update ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_folder_success() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create
    let body = common::make_folder_body("Original Name");
    let resp = app
        .post_json_auth("/api/v1/vault/folders", &body, &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let folder_id = json["data"]["id"].as_str().unwrap();

    // Update
    let update_body = serde_json::json!({
        "name_encrypted": base64::engine::general_purpose::STANDARD.encode(b"Updated Name")
    });
    let resp = app
        .put_json_auth(
            &format!("/api/v1/vault/folders/{}", folder_id),
            &update_body,
            &token,
        )
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["success"], true);
    assert!(json["data"]["name_encrypted"].is_string());

    app.cleanup().await;
}

#[tokio::test]
async fn update_nonexistent_folder_returns_404() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    let update_body = serde_json::json!({
        "name_encrypted": base64::engine::general_purpose::STANDARD.encode(b"Ghost")
    });
    let resp = app
        .put_json_auth(
            "/api/v1/vault/folders/aaaaaaaaaaaaaaaaaaaaaaaa",
            &update_body,
            &token,
        )
        .await;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    app.cleanup().await;
}

// ─── Delete ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_folder_success() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create
    let body = common::make_folder_body("To Delete");
    let resp = app
        .post_json_auth("/api/v1/vault/folders", &body, &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let folder_id = json["data"]["id"].as_str().unwrap();

    // Delete
    let resp = app
        .delete_auth(&format!("/api/v1/vault/folders/{}", folder_id), &token)
        .await;
    common::assert_status_and_json(resp, StatusCode::OK).await;

    // Verify it's gone
    let resp = app.get_auth("/api/v1/vault/folders", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["data"].as_array().unwrap().len(), 0);

    app.cleanup().await;
}

#[tokio::test]
async fn delete_nonexistent_folder_returns_404() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    let resp = app
        .delete_auth(
            "/api/v1/vault/folders/aaaaaaaaaaaaaaaaaaaaaaaa",
            &token,
        )
        .await;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    app.cleanup().await;
}

// ─── User Isolation ─────────────────────────────────────────────────────────

#[tokio::test]
async fn folders_are_isolated_per_user() {
    let app = common::TestApp::new().await;

    // User A
    let (s, _) = app
        .register_user("alice@test.com", "AlicePass1!", "Alice")
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, _, token_a, _) = app.login_user("alice@test.com", "AlicePass1!").await;
    let token_a = token_a.unwrap();

    // User B
    let (s, _) = app
        .register_user("bob@test.com", "BobPass2!", "Bob")
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, _, token_b, _) = app.login_user("bob@test.com", "BobPass2!").await;
    let token_b = token_b.unwrap();

    // Alice creates a folder
    let body = common::make_folder_body("Alice's Secret Folder");
    app.post_json_auth("/api/v1/vault/folders", &body, &token_a)
        .await;

    // Bob sees nothing
    let resp = app.get_auth("/api/v1/vault/folders", &token_b).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["data"].as_array().unwrap().len(), 0);

    // Alice sees her folder
    let resp = app.get_auth("/api/v1/vault/folders", &token_a).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["data"].as_array().unwrap().len(), 1);

    app.cleanup().await;
}
