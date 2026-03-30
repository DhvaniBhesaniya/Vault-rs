use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};

/// Security headers middleware.
///
/// Adds standard security headers to every response:
/// - Strict-Transport-Security (HSTS)
/// - X-Content-Type-Options
/// - X-Frame-Options
/// - X-XSS-Protection
/// - Content-Security-Policy
/// - Referrer-Policy
/// - Permissions-Policy
pub async fn security_headers_middleware(
    req: Request,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    );
    headers.insert(
        "x-content-type-options",
        "nosniff".parse().unwrap(),
    );
    headers.insert(
        "x-frame-options",
        "DENY".parse().unwrap(),
    );
    headers.insert(
        "x-xss-protection",
        "1; mode=block".parse().unwrap(),
    );
    headers.insert(
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()".parse().unwrap(),
    );
    headers.insert(
        "cache-control",
        "no-store, no-cache, must-revalidate".parse().unwrap(),
    );

    response
}
