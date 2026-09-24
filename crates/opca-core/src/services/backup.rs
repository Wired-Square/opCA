//! Encrypted backup file format for OPCA vault exports.
//!
//! File layout:
//! ```text
//! Bytes 0-3:    Magic (b"OPCA")
//! Byte  4:      Format version (0x01)
//! Bytes 5-20:   PBKDF2 salt (16 bytes)
//! Bytes 21-32:  AES-GCM nonce (12 bytes)
//! Bytes 33-48:  GCM authentication tag (16 bytes)
//! Bytes 49-N:   AES-256-GCM ciphertext
//! ```
//!
//! Encryption uses AES-256-GCM with a key derived from a user password
//! via PBKDF2-HMAC-SHA256 (600,000 iterations). Data never touches disk
//! unencrypted.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

use crate::error::OpcaError;

// --- constants ---------------------------------------------------------------

const BACKUP_MAGIC: &[u8; 4] = b"OPCA";
const BACKUP_VERSION: u8 = 1;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const PBKDF2_ITERATIONS: u32 = 600_000;
const KEY_LENGTH: usize = 32; // AES-256

const HEADER_LENGTH: usize = 4 + 1 + SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH; // 49

// --- public API --------------------------------------------------------------

/// Encrypt `plaintext` with `password` and return the full backup blob.
///
/// The returned bytes include the OPCA header followed by the ciphertext.
/// The format is bit-compatible with the Python implementation.
pub fn encrypt_payload(plaintext: &[u8], password: &str) -> Result<Vec<u8>, OpcaError> {
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| OpcaError::Crypto(format!("Failed to create cipher: {e}")))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // aes-gcm crate's encrypt returns ciphertext || tag (tag appended)
    let ct_with_tag = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: b"" })
        .map_err(|e| OpcaError::Crypto(format!("Encryption failed: {e}")))?;

    // Split: ciphertext is everything except the last TAG_LENGTH bytes
    let ct_len = ct_with_tag.len() - TAG_LENGTH;
    let ciphertext = &ct_with_tag[..ct_len];
    let tag = &ct_with_tag[ct_len..];

    // Build output: MAGIC + VERSION + SALT + NONCE + TAG + CIPHERTEXT
    let mut output = Vec::with_capacity(HEADER_LENGTH + ciphertext.len());
    output.extend_from_slice(BACKUP_MAGIC);
    output.push(BACKUP_VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(tag);
    output.extend_from_slice(ciphertext);

    Ok(output)
}

/// Decrypt a backup blob produced by [`encrypt_payload`].
pub fn decrypt_payload(data: &[u8], password: &str) -> Result<Vec<u8>, OpcaError> {
    if data.len() < HEADER_LENGTH {
        return Err(OpcaError::BackupFormat(
            "File is too small to be a valid OPCA backup.".to_string(),
        ));
    }

    let magic = &data[..4];
    if magic != BACKUP_MAGIC {
        return Err(OpcaError::BackupFormat(format!(
            "Invalid file: expected magic {:?}, got {magic:?}.",
            BACKUP_MAGIC
        )));
    }

    let version = data[4];
    if version != BACKUP_VERSION {
        return Err(OpcaError::BackupFormat(format!(
            "Unsupported backup version {version}; this tool supports version {BACKUP_VERSION}."
        )));
    }

    let salt = &data[5..21];
    let nonce_bytes = &data[21..33];
    let tag = &data[33..49];
    let ciphertext = &data[49..];

    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| OpcaError::Crypto(format!("Failed to create cipher: {e}")))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    // Reconstruct ciphertext || tag for the aes-gcm crate
    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + TAG_LENGTH);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    let plaintext = cipher
        .decrypt(nonce, Payload { msg: &ct_with_tag, aad: b"" })
        .map_err(|_| OpcaError::BackupDecryption)?;

    Ok(plaintext)
}

// --- internals ---------------------------------------------------------------

/// Derive a 256-bit key from `password` and `salt` using PBKDF2-HMAC-SHA256.
fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

// --- tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, OPCA backup!";
        let password = "test-password-123";

        let encrypted = encrypt_payload(plaintext, password).unwrap();
        let decrypted = decrypt_payload(&encrypted, password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_payload() {
        let encrypted = encrypt_payload(b"", "pw").unwrap();
        let decrypted = decrypt_payload(&encrypted, "pw").unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_encrypt_decrypt_large_payload() {
        let plaintext = vec![0xABu8; 100_000];
        let encrypted = encrypt_payload(&plaintext, "pw").unwrap();
        let decrypted = decrypt_payload(&encrypted, "pw").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let encrypted = encrypt_payload(b"secret", "correct").unwrap();
        let result = decrypt_payload(&encrypted, "wrong");
        assert!(result.is_err());
        match result.unwrap_err() {
            OpcaError::BackupDecryption => {}
            other => panic!("Expected BackupDecryption, got {other:?}"),
        }
    }

    #[test]
    fn test_truncated_data_fails() {
        let result = decrypt_payload(b"OPCA", "pw");
        assert!(result.is_err());
        match result.unwrap_err() {
            OpcaError::BackupFormat(_) => {}
            other => panic!("Expected BackupFormat, got {other:?}"),
        }
    }

    #[test]
    fn test_bad_magic_fails() {
        let mut data = vec![0u8; HEADER_LENGTH + 10];
        data[..4].copy_from_slice(b"NOPE");
        let result = decrypt_payload(&data, "pw");
        assert!(result.is_err());
        match result.unwrap_err() {
            OpcaError::BackupFormat(msg) => assert!(msg.contains("magic")),
            other => panic!("Expected BackupFormat, got {other:?}"),
        }
    }

    #[test]
    fn test_bad_version_fails() {
        let mut data = vec![0u8; HEADER_LENGTH + 10];
        data[..4].copy_from_slice(BACKUP_MAGIC);
        data[4] = 99; // unsupported version
        let result = decrypt_payload(&data, "pw");
        assert!(result.is_err());
        match result.unwrap_err() {
            OpcaError::BackupFormat(msg) => assert!(msg.contains("version")),
            other => panic!("Expected BackupFormat, got {other:?}"),
        }
    }

    #[test]
    fn test_header_structure() {
        let encrypted = encrypt_payload(b"test", "pw").unwrap();

        // Verify header layout
        assert_eq!(&encrypted[..4], BACKUP_MAGIC);
        assert_eq!(encrypted[4], BACKUP_VERSION);
        assert!(encrypted.len() > HEADER_LENGTH);
    }

    #[test]
    fn test_unique_salt_and_nonce() {
        let e1 = encrypt_payload(b"same", "pw").unwrap();
        let e2 = encrypt_payload(b"same", "pw").unwrap();

        // Salt (bytes 5-20) and nonce (bytes 21-32) should differ
        assert_ne!(&e1[5..21], &e2[5..21]);
        assert_ne!(&e1[21..33], &e2[21..33]);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let mut encrypted = encrypt_payload(b"test data", "pw").unwrap();
        // Flip a byte in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        let result = decrypt_payload(&encrypted, "pw");
        assert!(result.is_err());
    }
}
