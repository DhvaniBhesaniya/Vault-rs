//! Integration tests for the Health endpoints.
//!
//! - GET /api/v1/health      — basic liveness check
//! - GET /api/v1/health/ready — readiness check (verifies MongoDB connectivity)

mod common;

use axum::http::StatusCode;

#[tokio::test]
async fn health_check_returns_ok() {
    let app = common::TestApp::new().await;

    let resp = app.get("/api/v1/health").await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["success"], true);
    assert_eq!(json["data"]["status"], "ok");
    assert!(json["data"]["version"].is_string());

    app.cleanup().await;
}

#[tokio::test]
async fn readiness_check_returns_ready() {
    let app = common::TestApp::new().await;

    let resp = app.get("/api/v1/health/ready").await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    assert_eq!(json["success"], true);
    assert_eq!(json["data"]["status"], "ready");

    app.cleanup().await;
}

#[tokio::test]
async fn health_response_includes_timestamp() {
    let app = common::TestApp::new().await;

    let resp = app.get("/api/v1/health").await;
    let json = common::assert_status_and_json(resp, StatusCode::OK).await;

    // Meta should contain a timestamp
    assert!(json["meta"]["timestamp"].is_string());

    app.cleanup().await;
}
