use validator::Validate;

use crate::errors::AppError;

/// Validate a request DTO using the `validator` crate.
pub fn validate_request<T: Validate>(req: &T) -> Result<(), AppError> {
    req.validate().map_err(|e| {
        let messages: Vec<String> = e
            .field_errors()
            .into_iter()
            .flat_map(|(field, errors)| {
                errors.iter().map(move |err| {
                    format!(
                        "{}: {}",
                        field,
                        err.message.as_deref().unwrap_or("invalid value")
                    )
                })
            })
            .collect();
        AppError::Validation(messages.join("; "))
    })
}

/// Validate that a string is a valid MongoDB ObjectId.
pub fn validate_object_id(id: &str) -> Result<mongodb::bson::oid::ObjectId, AppError> {
    mongodb::bson::oid::ObjectId::parse_str(id)
        .map_err(|_| AppError::Validation(format!("Invalid ID format: {}", id)))
}
