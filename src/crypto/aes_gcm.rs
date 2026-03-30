use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;

use crate::errors::AppError;

/// AES-256-GCM nonce size in bytes (96 bits).
pub const NONCE_SIZE: usize = 12;

/// Generate a random 96-bit nonce for AES-GCM.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Generate a random 256-bit symmetric key.
pub fn generate_symmetric_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt plaintext using AES-256-GCM.
///
/// Returns `(nonce, ciphertext)` where ciphertext includes the 128-bit auth tag.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AppError::Crypto(format!("AES-256-GCM encryption failed: {}", e)))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt ciphertext using AES-256-GCM.
///
/// The ciphertext must include the 128-bit auth tag appended by the encrypt function.
pub fn decrypt(key: &[u8; 32], nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AppError> {
    if nonce_bytes.len() != NONCE_SIZE {
        return Err(AppError::Crypto(format!(
            "Invalid nonce size: expected {}, got {}",
            NONCE_SIZE,
            nonce_bytes.len()
        )));
    }

    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AppError::Crypto(format!("AES-256-GCM decryption failed: {}", e)))?;

    Ok(plaintext)
}

/// Encrypt a symmetric key with a master key (key wrapping).
///
/// Used to create the `protected_symmetric_key`.
pub fn wrap_key(master_key: &[u8; 32], symmetric_key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    encrypt(master_key, symmetric_key)
}

/// Decrypt a wrapped symmetric key using the master key.
pub fn unwrap_key(
    master_key: &[u8; 32],
    nonce: &[u8],
    wrapped_key: &[u8],
) -> Result<[u8; 32], AppError> {
    let decrypted = decrypt(master_key, nonce, wrapped_key)?;
    if decrypted.len() != 32 {
        return Err(AppError::Crypto(format!(
            "Unwrapped key has invalid length: expected 32, got {}",
            decrypted.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decrypted);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_symmetric_key();
        let plaintext = b"Hello, RustVault!";

        let (nonce, ciphertext) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_symmetric_key();
        let key2 = generate_symmetric_key();
        let plaintext = b"Secret data";

        let (nonce, ciphertext) = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_key_wrap_unwrap() {
        let master_key = generate_symmetric_key();
        let sym_key = generate_symmetric_key();

        let (nonce, wrapped) = wrap_key(&master_key, &sym_key).unwrap();
        let unwrapped = unwrap_key(&master_key, &nonce, &wrapped).unwrap();

        assert_eq!(unwrapped, sym_key);
    }
}
