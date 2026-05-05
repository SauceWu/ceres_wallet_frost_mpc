//! AES-256-GCM + HKDF-SHA256 backup encryption for FROST keyshares.
//!
//! Equivalent to the secp256k1 backup path in ceres_wallet_mpc/mpc_engine.rs.
//! Wire format: nonce(12B) || ciphertext, hex-encoded, stored in BackupEnvelope.payload.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::types::BackupEnvelope;

const HKDF_INFO: &[u8] = b"ceres-mpc-backup-v1";

fn derive_aes_key(user_backup_secret: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, user_backup_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("32 bytes is valid HKDF-SHA256 output length");
    key
}

fn encrypt(plaintext: &[u8], key_bytes: &[u8; 32]) -> Result<String, String> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("aes-gcm encrypt failed: {e}"))?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(hex::encode(combined))
}

fn decrypt(payload_hex: &str, key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    let combined =
        hex::decode(payload_hex).map_err(|e| format!("hex decode failed: {e}"))?;
    if combined.len() < 12 {
        return Err("payload too short: must be at least 12 bytes (nonce)".to_string());
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "aes-gcm decrypt failed: wrong key or corrupted payload".to_string())
}

/// Encrypt `local_encrypted_share` with `user_backup_secret` and return a
/// JSON-encoded `BackupEnvelope`.
///
/// The share string is encrypted as raw UTF-8 bytes. The nonce is randomly
/// generated each call, so repeated calls produce different ciphertexts.
pub fn derive_backup_envelope(
    local_encrypted_share: &str,
    user_backup_secret: &str,
    created_at: &str,
) -> Result<String, String> {
    let key = derive_aes_key(user_backup_secret);
    let payload = encrypt(local_encrypted_share.as_bytes(), &key)?;
    let envelope = BackupEnvelope {
        version: "1".to_string(),
        algorithm: "aes-256-gcm-hkdf-sha256".to_string(),
        created_at: created_at.to_string(),
        payload,
    };
    serde_json::to_string(&envelope).map_err(|e| e.to_string())
}

/// Decrypt a `BackupEnvelope` JSON string and return the plaintext share.
pub fn decrypt_backup_share(
    encrypted_envelope: &str,
    user_backup_secret: &str,
) -> Result<String, String> {
    let envelope: BackupEnvelope = serde_json::from_str(encrypted_envelope)
        .map_err(|e| format!("invalid BackupEnvelope JSON: {e}"))?;
    let key = derive_aes_key(user_backup_secret);
    let plaintext = decrypt(&envelope.payload, &key)?;
    String::from_utf8(plaintext)
        .map_err(|e| format!("decrypted bytes are not valid UTF-8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARE: &str = "eyJ2IjoyLCJjdXJ2ZSI6ImVkMjU1MTkiLCJzaGFyZSI6InRlc3QifQ==";
    const SECRET: &str = "my-backup-secret";
    const CREATED_AT: &str = "2026-01-01";

    #[test]
    fn test_roundtrip() {
        let envelope = derive_backup_envelope(SHARE, SECRET, CREATED_AT).unwrap();
        let recovered = decrypt_backup_share(&envelope, SECRET).unwrap();
        assert_eq!(recovered, SHARE);
    }

    #[test]
    fn test_wrong_secret_fails() {
        let envelope = derive_backup_envelope(SHARE, SECRET, CREATED_AT).unwrap();
        let err = decrypt_backup_share(&envelope, "wrong-secret").unwrap_err();
        assert_eq!(err, "aes-gcm decrypt failed: wrong key or corrupted payload");
    }

    #[test]
    fn test_backup_envelope_fields() {
        let envelope_json = derive_backup_envelope(SHARE, SECRET, CREATED_AT).unwrap();
        let env: BackupEnvelope = serde_json::from_str(&envelope_json).unwrap();
        assert_eq!(env.version, "1");
        assert_eq!(env.algorithm, "aes-256-gcm-hkdf-sha256");
        assert_eq!(env.created_at, CREATED_AT);
        assert!(!env.payload.is_empty());
    }

    #[test]
    fn test_random_nonce_produces_different_ciphertexts() {
        let e1 = derive_backup_envelope(SHARE, SECRET, CREATED_AT).unwrap();
        let e2 = derive_backup_envelope(SHARE, SECRET, CREATED_AT).unwrap();
        let env1: BackupEnvelope = serde_json::from_str(&e1).unwrap();
        let env2: BackupEnvelope = serde_json::from_str(&e2).unwrap();
        assert_ne!(env1.payload, env2.payload);
    }
}
