//! Integration tests for the Vault Item endpoints.
//!
//! - POST   /api/v1/vault/items              — create item
//! - GET    /api/v1/vault/items              — list items
//! - GET    /api/v1/vault/items/{id}         — get single item
//! - PUT    /api/v1/vault/items/{id}         — update item
//! - DELETE /api/v1/vault/items/{id}         — soft delete
//! - GET    /api/v1/vault/items/trash        — list trash
//! - POST   /api/v1/vault/items/{id}/restore — restore from trash
//! - DELETE /api/v1/vault/items/{id}/permanent — permanent delete

mod common;

use axum::http::StatusCode;

// ─── Create ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_vault_item_success() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    let body = common::make_vault_item_body("login", "My Website Login");
    let resp = app
        .post_json_auth("/api/v1/vault/items", &body, &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["success"], true);
    assert!(json["data"]["id"].is_string());
    assert_eq!(json["data"]["item_type"], "login");
    assert_eq!(json["data"]["favorite"], false);
    assert_eq!(json["data"]["tags"][0], "test");

    app.cleanup().await;
}

#[tokio::test]
async fn create_vault_item_different_types() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    let types = ["login", "card", "identity", "secure_note"];

    for item_type in types {
        let body = common::make_vault_item_body(item_type, &format!("Test {}", item_type));
        let resp = app
            .post_json_auth("/api/v1/vault/items", &body, &token)
            .await;
        let json = common::assert_status_and_json(resp, StatusCode::OK).await;
        assert_eq!(json["data"]["item_type"], item_type);
    }

    app.cleanup().await;
}

#[tokio::test]
async fn create_vault_item_without_auth_fails() {
    let app = common::TestApp::new().await;

    let body = common::make_vault_item_body("login", "Unauthorized Item");
    let resp = app.post_json("/api/v1/vault/items", &body).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    app.cleanup().await;
}

// ─── List ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_vault_items_empty() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    let resp = app.get_auth("/api/v1/vault/items", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["success"], true);
    assert!(json["data"].is_array());
    assert_eq!(json["data"].as_array().unwrap().len(), 0);

    app.cleanup().await;
}

#[tokio::test]
async fn list_vault_items_returns_created_items() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create 3 items
    for i in 0..3 {
        let body = common::make_vault_item_body("login", &format!("Item {}", i));
        let resp = app
            .post_json_auth("/api/v1/vault/items", &body, &token)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // List them
    let resp = app.get_auth("/api/v1/vault/items", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    let items = json["data"].as_array().unwrap();
    assert_eq!(items.len(), 3);

    app.cleanup().await;
}

#[tokio::test]
async fn list_vault_items_with_pagination() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create 5 items
    for i in 0..5 {
        let body = common::make_vault_item_body("login", &format!("Item {}", i));
        app.post_json_auth("/api/v1/vault/items", &body, &token)
            .await;
    }

    // List with pagination: page 1, 2 per page
    let resp = app
        .get_auth("/api/v1/vault/items?page=1&per_page=2", &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    let items = json["data"].as_array().unwrap();
    assert_eq!(items.len(), 2);

    // Check pagination metadata
    if let Some(pagination) = json["meta"]["pagination"].as_object() {
        assert_eq!(pagination["page"], 1);
        assert_eq!(pagination["per_page"], 2);
        assert_eq!(pagination["total"], 5);
    }

    app.cleanup().await;
}

// ─── Get Single ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_vault_item_by_id() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create an item
    let body = common::make_vault_item_body("login", "Single Item");
    let resp = app
        .post_json_auth("/api/v1/vault/items", &body, &token)
        .await;
    let create_json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let item_id = create_json["data"]["id"].as_str().unwrap();

    // Get it by ID
    let resp = app
        .get_auth(&format!("/api/v1/vault/items/{}", item_id), &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["data"]["id"], item_id);
    assert_eq!(json["data"]["item_type"], "login");

    app.cleanup().await;
}

#[tokio::test]
async fn get_nonexistent_vault_item_returns_404() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Use a valid ObjectId format that doesn't exist
    let resp = app
        .get_auth("/api/v1/vault/items/aaaaaaaaaaaaaaaaaaaaaaaa", &token)
        .await;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    app.cleanup().await;
}

// ─── Update ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_vault_item_success() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create
    let body = common::make_vault_item_body("login", "Original");
    let resp = app
        .post_json_auth("/api/v1/vault/items", &body, &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let item_id = json["data"]["id"].as_str().unwrap();

    // Update
    let update_body = serde_json::json!({
        "favorite": true,
        "tags": ["updated", "important"]
    });
    let resp = app
        .put_json_auth(
            &format!("/api/v1/vault/items/{}", item_id),
            &update_body,
            &token,
        )
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["data"]["favorite"], true);
    let tags = json["data"]["tags"].as_array().unwrap();
    assert!(tags.iter().any(|t| t == "updated"));
    assert!(tags.iter().any(|t| t == "important"));

    app.cleanup().await;
}

// ─── Soft Delete & Trash ────────────────────────────────────────────────────

#[tokio::test]
async fn soft_delete_and_list_trash() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create
    let body = common::make_vault_item_body("login", "To be trashed");
    let resp = app
        .post_json_auth("/api/v1/vault/items", &body, &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let item_id = json["data"]["id"].as_str().unwrap();

    // Soft delete
    let resp = app
        .delete_auth(&format!("/api/v1/vault/items/{}", item_id), &token)
        .await;
    common::assert_status_and_json(resp, StatusCode::OK).await;

    // Verify it's gone from normal list
    let resp = app.get_auth("/api/v1/vault/items", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["data"].as_array().unwrap().len(), 0);

    // Verify it appears in trash
    let resp = app.get_auth("/api/v1/vault/items/trash", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let trash = json["data"].as_array().unwrap();
    assert_eq!(trash.len(), 1);
    assert_eq!(trash[0]["id"], item_id);

    app.cleanup().await;
}

// ─── Restore ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn restore_from_trash() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create and soft-delete
    let body = common::make_vault_item_body("login", "Restorable");
    let resp = app
        .post_json_auth("/api/v1/vault/items", &body, &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let item_id = json["data"]["id"].as_str().unwrap();

    app.delete_auth(&format!("/api/v1/vault/items/{}", item_id), &token)
        .await;

    // Restore
    let resp = app
        .post_json_auth(
            &format!("/api/v1/vault/items/{}/restore", item_id),
            &serde_json::json!({}),
            &token,
        )
        .await;
    common::assert_status_and_json(resp, StatusCode::OK).await;

    // Verify it's back in the normal list
    let resp = app.get_auth("/api/v1/vault/items", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let items = json["data"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], item_id);

    // Verify trash is empty
    let resp = app.get_auth("/api/v1/vault/items/trash", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["data"].as_array().unwrap().len(), 0);

    app.cleanup().await;
}

// ─── Permanent Delete ───────────────────────────────────────────────────────

#[tokio::test]
async fn permanent_delete() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create an item
    let body = common::make_vault_item_body("login", "Gone forever");
    let resp = app
        .post_json_auth("/api/v1/vault/items", &body, &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let item_id = json["data"]["id"].as_str().unwrap();

    // Permanent delete
    let resp = app
        .delete_auth(
            &format!("/api/v1/vault/items/{}/permanent", item_id),
            &token,
        )
        .await;
    common::assert_status_and_json(resp, StatusCode::OK).await;

    // Should not appear in normal list or trash
    let resp = app.get_auth("/api/v1/vault/items", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["data"].as_array().unwrap().len(), 0);

    let resp = app.get_auth("/api/v1/vault/items/trash", &token).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["data"].as_array().unwrap().len(), 0);

    // Getting by ID should return 404
    let resp = app
        .get_auth(&format!("/api/v1/vault/items/{}", item_id), &token)
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    app.cleanup().await;
}

// ─── User Isolation ─────────────────────────────────────────────────────────

#[tokio::test]
async fn users_cannot_see_each_others_items() {
    let app = common::TestApp::new().await;

    // Register and login user A
    let (status, _) = app
        .register_user("alice@example.com", "AliceP@ss1!", "Alice")
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, _, token_a, _) = app.login_user("alice@example.com", "AliceP@ss1!").await;
    let token_a = token_a.unwrap();

    // Register and login user B
    let (status, _) = app
        .register_user("bob@example.com", "BobP@ss2!", "Bob")
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, _, token_b, _) = app.login_user("bob@example.com", "BobP@ss2!").await;
    let token_b = token_b.unwrap();

    // Alice creates an item
    let body = common::make_vault_item_body("login", "Alice's secret");
    let resp = app
        .post_json_auth("/api/v1/vault/items", &body, &token_a)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Bob lists items — should see nothing
    let resp = app.get_auth("/api/v1/vault/items", &token_b).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["data"].as_array().unwrap().len(), 0);

    // Alice lists items — should see her item
    let resp = app.get_auth("/api/v1/vault/items", &token_a).await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;
    assert_eq!(json["data"].as_array().unwrap().len(), 1);

    app.cleanup().await;
}

// ─── Create with Folder ─────────────────────────────────────────────────────

#[tokio::test]
async fn create_vault_item_with_folder() {
    let app = common::TestApp::new().await;
    let (token, _) = app.register_and_login().await;

    // Create a folder first
    let folder_body = common::make_folder_body("Work Credentials");
    let resp = app
        .post_json_auth("/api/v1/vault/folders", &folder_body, &token)
        .await;
    let folder_json = common::assert_status_and_json(resp, StatusCode::OK).await;
    let folder_id = folder_json["data"]["id"].as_str().unwrap();

    // Create a vault item in that folder
    let mut item_body = common::make_vault_item_body("login", "Work Login");
    item_body["folder_id"] = serde_json::json!(folder_id);

    let resp = app
        .post_json_auth("/api/v1/vault/items", &item_body, &token)
        .await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["data"]["folder_id"], folder_id);

    app.cleanup().await;
}
