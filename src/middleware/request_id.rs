use axum::{
    extract::Request,
    http::HeaderValue,
    middleware::Next,
    response::Response,
};

/// Middleware to inject or retrieve the X-Request-ID header.
///
/// If the client sends an X-Request-ID, it is preserved.
/// Otherwise, a new UUID is generated and added.
pub async fn request_id_middleware(
    mut req: Request,
    next: Next,
) -> Response {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Store in extensions for handlers to access
    req.extensions_mut().insert(RequestId(request_id.clone()));

    let mut response = next.run(req).await;

    // Echo request ID in response
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }

    response
}

/// Wrapper type for the request ID stored in extensions.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);
