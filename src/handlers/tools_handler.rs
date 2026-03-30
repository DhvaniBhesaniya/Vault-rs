use axum::Json;

use crate::crypto::password_generator::{
    generate_passphrase, generate_password, PassphraseOptions, PasswordOptions,
};
use crate::dto::common_dto::{success_response, ApiResponse};
use crate::dto::vault_dto::*;
use crate::errors::AppError;

/// POST /api/v1/tools/generate-password
pub async fn generate_password_handler(
    Json(req): Json<GeneratePasswordRequest>,
) -> Result<Json<ApiResponse<GeneratePasswordResponse>>, AppError> {
    let options = PasswordOptions {
        length: req.length.unwrap_or(20).min(128).max(8),
        uppercase: req.uppercase.unwrap_or(true),
        lowercase: req.lowercase.unwrap_or(true),
        numbers: req.numbers.unwrap_or(true),
        symbols: req.symbols.unwrap_or(true),
        exclude_ambiguous: req.exclude_ambiguous.unwrap_or(false),
    };

    let password = generate_password(&options);

    Ok(Json(success_response(
        GeneratePasswordResponse { password },
        None,
    )))
}

/// POST /api/v1/tools/generate-passphrase
pub async fn generate_passphrase_handler(
    Json(req): Json<GeneratePassphraseRequest>,
) -> Result<Json<ApiResponse<GeneratePassphraseResponse>>, AppError> {
    let options = PassphraseOptions {
        num_words: req.num_words.unwrap_or(5).min(10).max(3),
        separator: req.separator.unwrap_or_else(|| "-".to_string()),
        capitalize: req.capitalize.unwrap_or(true),
        include_number: req.include_number.unwrap_or(true),
    };

    let passphrase = generate_passphrase(&options);

    Ok(Json(success_response(
        GeneratePassphraseResponse { passphrase },
        None,
    )))
}

/// POST /api/v1/tools/check-breach
///
/// Checks if a password hash appears in the HIBP database using k-Anonymity.
/// The client sends the first 5 characters of the SHA-1 hash.
pub async fn check_breach_handler(
    Json(req): Json<CheckBreachRequest>,
) -> Result<Json<ApiResponse<CheckBreachResponse>>, AppError> {
    let prefix = &req.sha1_hash[..5.min(req.sha1_hash.len())];
    let suffix = &req.sha1_hash[5.min(req.sha1_hash.len())..];

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("User-Agent", "RustVault-PasswordManager")
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("HIBP API request failed: {}", e)))?;

    let body = response
        .text()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read HIBP response: {}", e)))?;

    let suffix_upper = suffix.to_uppercase();
    let mut breach_count: u64 = 0;
    let mut breached = false;

    for line in body.lines() {
        if let Some((hash_suffix, count_str)) = line.split_once(':') {
            if hash_suffix.trim() == suffix_upper {
                breach_count = count_str.trim().parse().unwrap_or(0);
                breached = true;
                break;
            }
        }
    }

    Ok(Json(success_response(
        CheckBreachResponse {
            breached,
            count: breach_count,
        },
        None,
    )))
}
