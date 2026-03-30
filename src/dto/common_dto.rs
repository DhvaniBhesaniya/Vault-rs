use serde::{Deserialize, Serialize};

/// Standard paginated response wrapper.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub meta: ResponseMeta,
}

#[derive(Debug, Serialize)]
pub struct ResponseMeta {
    pub request_id: Option<String>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PaginationMeta>,
}

#[derive(Debug, Serialize)]
pub struct PaginationMeta {
    pub page: u64,
    pub per_page: u64,
    pub total: u64,
    pub total_pages: u64,
}

/// Query parameters for paginated list endpoints.
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}

impl PaginationParams {
    pub fn page(&self) -> u64 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn per_page(&self) -> u64 {
        self.per_page.unwrap_or(50).min(100).max(1)
    }

    pub fn skip(&self) -> u64 {
        (self.page() - 1) * self.per_page()
    }
}

/// Helper to build a success response.
pub fn success_response<T: Serialize>(data: T, request_id: Option<String>) -> ApiResponse<T> {
    ApiResponse {
        success: true,
        data: Some(data),
        meta: ResponseMeta {
            request_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            pagination: None,
        },
    }
}

/// Helper to build a paginated success response.
pub fn paginated_response<T: Serialize>(
    data: T,
    request_id: Option<String>,
    page: u64,
    per_page: u64,
    total: u64,
) -> ApiResponse<T> {
    let total_pages = (total + per_page - 1) / per_page;
    ApiResponse {
        success: true,
        data: Some(data),
        meta: ResponseMeta {
            request_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            pagination: Some(PaginationMeta {
                page,
                per_page,
                total,
                total_pages,
            }),
        },
    }
}

/// A simple message response.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}
