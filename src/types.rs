//! Key serialization types for FROST-Ed25519.
//!
//! ShareEnvelope: v2 curve-tagged keyshare wrapper (encode/decode).
//! ExportResult: returned by export_private_key.
//! BackupEnvelope: returned by derive_backup_envelope.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

// ── ShareEnvelope ─────────────────────────────────────────────────────────────

/// v2 curve-tagged keyshare wrapper.
/// encode/decode are symmetric with build_share_envelope in export.rs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareEnvelope {
    pub v: u8,
    pub curve: String,
    /// base64-encoded inner share material
    pub share: String,
}

impl ShareEnvelope {
    /// Encode self as base64(json(self)).
    pub fn encode(&self) -> Result<String, String> {
        let json = serde_json::to_string(self)
            .map_err(|e| format!("ShareEnvelope encode: {e}"))?;
        Ok(BASE64.encode(json.as_bytes()))
    }

    /// Decode from a base64 string.
    ///
    /// Strategy:
    ///   1. base64-decode the input.
    ///   2. Try to parse as JSON ShareEnvelope (v2 path).
    ///   3. On parse failure, treat raw bytes as legacy secp256k1 share
    ///      (hex-encode the raw bytes as the `share` field, v=0).
    pub fn decode(encoded: &str) -> Result<Self, String> {
        let bytes = BASE64
            .decode(encoded)
            .map_err(|e| format!("ShareEnvelope base64 decode: {e}"))?;

        if let Ok(env) = serde_json::from_slice::<ShareEnvelope>(&bytes) {
            return Ok(env);
        }

        // Legacy fallback: raw bytes → secp256k1
        Ok(ShareEnvelope {
            v: 0,
            curve: "secp256k1".to_string(),
            share: hex::encode(&bytes),
        })
    }
}

// ── ExportResult ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub private_key: String,
    pub exported: bool,
}

// ── BackupEnvelope ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEnvelope {
    pub version: String,
    pub algorithm: String,
    pub created_at: String,
    pub payload: String,
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_envelope_decode_v2() {
        let inner = ShareEnvelope {
            v: 2,
            curve: "ed25519".to_string(),
            share: "c2hhcmU=".to_string(),
        };
        let encoded = inner.encode().unwrap();
        let decoded = ShareEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.v, 2);
        assert_eq!(decoded.curve, "ed25519");
        assert_eq!(decoded.share, "c2hhcmU=");
    }

    #[test]
    fn test_share_envelope_decode_legacy_fallback() {
        let raw_bytes = b"\x01\x02\x03\x04";
        let encoded = BASE64.encode(raw_bytes);
        let result = ShareEnvelope::decode(&encoded).unwrap();
        assert_eq!(result.v, 0);
        assert_eq!(result.curve, "secp256k1");
        assert_eq!(result.share, hex::encode(raw_bytes));
    }

    #[test]
    fn test_export_result_roundtrip() {
        let r = ExportResult {
            private_key: "deadbeef".to_string(),
            exported: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: ExportResult = serde_json::from_str(&json).unwrap();
        assert!(r2.exported);
    }

    #[test]
    fn test_backup_envelope_roundtrip() {
        let b = BackupEnvelope {
            version: "1".to_string(),
            algorithm: "aes-256-gcm-hkdf-sha256".to_string(),
            created_at: "2026-01-01".to_string(),
            payload: "ciphertext==".to_string(),
        };
        let json = serde_json::to_string(&b).unwrap();
        let b2: BackupEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(b2.algorithm, "aes-256-gcm-hkdf-sha256");
        assert_eq!(b2.version, "1");
    }
}
