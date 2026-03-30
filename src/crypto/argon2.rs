use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

use crate::errors::AppError;

/// Create an Argon2id hasher with our configured parameters.
fn make_argon2(memory_kb: u32, iterations: u32, parallelism: u32) -> Result<Argon2<'static>, AppError> {
    let params = Params::new(memory_kb, iterations, parallelism, Some(32))
        .map_err(|e| AppError::Crypto(format!("Invalid Argon2 params: {}", e)))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive a 256-bit master key from the master password using Argon2id.
///
/// The email is used as the salt (normalized to lowercase).
/// Returns 32 bytes (256-bit) master key.
pub fn derive_master_key(
    master_password: &[u8],
    email: &str,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<[u8; 32], AppError> {
    let params = Params::new(memory_kb, iterations, parallelism, Some(32))
        .map_err(|e| AppError::Crypto(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Use email as salt (padded/hashed to meet salt requirements)
    let salt = email.to_lowercase();
    // Argon2 requires at least 8 bytes of salt
    let salt_bytes = if salt.len() < 8 {
        format!("{:0>8}", salt)
    } else {
        salt
    };

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(master_password, salt_bytes.as_bytes(), &mut output)
        .map_err(|e| AppError::Crypto(format!("Argon2id key derivation failed: {}", e)))?;

    Ok(output)
}

/// Hash a master password hash (the HKDF-derived auth hash) for server storage.
///
/// This performs Argon2id(master_pw_hash) with a random salt, producing a PHC-format string.
pub fn hash_for_storage(
    master_pw_hash: &[u8],
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<String, AppError> {
    let argon2 = make_argon2(memory_kb, iterations, parallelism)?;
    let salt = SaltString::generate(&mut OsRng);

    let hash = argon2
        .hash_password(master_pw_hash, &salt)
        .map_err(|e| AppError::Crypto(format!("Argon2id hash failed: {}", e)))?;

    Ok(hash.to_string())
}

/// Verify a master password hash against the stored hash.
pub fn verify_hash(master_pw_hash: &[u8], stored_hash: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(stored_hash)
        .map_err(|e| AppError::Crypto(format!("Invalid stored hash format: {}", e)))?;

    // Extract params from stored hash to reconstruct the correct hasher
    let params = Params::try_from(&parsed_hash)
        .map_err(|e| AppError::Crypto(format!("Failed to extract params from hash: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    match argon2.verify_password(master_pw_hash, &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AppError::Crypto(format!("Hash verification failed: {}", e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key() {
        let key = derive_master_key(b"test_password", "user@example.com", 1024, 1, 1).unwrap();
        assert_eq!(key.len(), 32);

        // Same inputs should produce the same key
        let key2 = derive_master_key(b"test_password", "user@example.com", 1024, 1, 1).unwrap();
        assert_eq!(key, key2);

        // Different password should produce different key
        let key3 = derive_master_key(b"other_password", "user@example.com", 1024, 1, 1).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_hash_and_verify() {
        let pw_hash = b"some_derived_hash_value_here1234";
        let stored = hash_for_storage(pw_hash, 1024, 1, 1).unwrap();

        assert!(verify_hash(pw_hash, &stored).unwrap());
        assert!(!verify_hash(b"wrong_hash_value_here1234567890", &stored).unwrap());
    }
}
