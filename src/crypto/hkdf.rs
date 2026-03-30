use hkdf::Hkdf;
use sha2::Sha256;

use crate::errors::AppError;

/// Derive the master password hash for authentication using HKDF-SHA256.
///
/// This derives a hash from the master key that is sent to the server for verification.
/// The server never sees the master key or master password.
///
/// `master_key` — 256-bit key derived from Argon2id(master_password, email)
/// Returns a 32-byte derived key suitable for sending to the server.
pub fn derive_master_password_hash(master_key: &[u8; 32], master_password: &[u8]) -> Result<[u8; 32], AppError> {
    // Use master_password as IKM and master_key as salt for HKDF
    // info = "master_password_hash" to domain-separate this derivation
    let hk = Hkdf::<Sha256>::new(Some(master_key), master_password);

    let mut output = [0u8; 32];
    hk.expand(b"master_password_hash", &mut output)
        .map_err(|e| AppError::Crypto(format!("HKDF expand failed: {}", e)))?;

    Ok(output)
}

/// Derive a sub-key from the master key for a specific purpose.
///
/// Used for domain separation when deriving multiple keys from a single master key.
pub fn derive_key(master_key: &[u8; 32], info: &[u8]) -> Result<[u8; 32], AppError> {
    let hk = Hkdf::<Sha256>::new(None, master_key);

    let mut output = [0u8; 32];
    hk.expand(info, &mut output)
        .map_err(|e| AppError::Crypto(format!("HKDF derive_key failed: {}", e)))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_password_hash() {
        let master_key = [0xABu8; 32];
        let password = b"my_master_password";

        let hash1 = derive_master_password_hash(&master_key, password).unwrap();
        let hash2 = derive_master_password_hash(&master_key, password).unwrap();

        // Deterministic
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Different password yields different hash
        let hash3 = derive_master_password_hash(&master_key, b"different").unwrap();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_derive_key() {
        let master_key = [0xCDu8; 32];

        let key1 = derive_key(&master_key, b"purpose_a").unwrap();
        let key2 = derive_key(&master_key, b"purpose_b").unwrap();

        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
    }
}
