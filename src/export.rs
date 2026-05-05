//! FROST key export — ShareEnvelope v2 builder and 2-of-2 Lagrange private key reconstruction.
//!
//! ShareEnvelope format:
//!   base64( json({ v:2, curve:"ed25519", share: base64( json({ kp: base64(kp_bytes), pkp: base64(pkp_bytes) }) ) }) )

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use serde::{Deserialize, Serialize};

use crate::error::FrostMpcError;
use crate::types::{ExportResult, ShareEnvelope};

/// Build a ShareEnvelope v2 string from the server's key packages.
/// The caller is responsible for tracking and enforcing the `exported` guard.
pub fn build_share_envelope(
    key_package: &frost_ed25519::keys::KeyPackage,
    public_key_package: &frost_ed25519::keys::PublicKeyPackage,
) -> Result<String, FrostMpcError> {
    let kp_bytes = key_package
        .serialize()
        .map_err(|e| FrostMpcError::Serialization(format!("serialize KeyPackage: {e}")))?;
    let pkp_bytes = public_key_package
        .serialize()
        .map_err(|e| FrostMpcError::Serialization(format!("serialize PublicKeyPackage: {e}")))?;

    let mat_json = serde_json::json!({
        "kp":  BASE64.encode(kp_bytes.as_ref() as &[u8]),
        "pkp": BASE64.encode(pkp_bytes.as_ref() as &[u8]),
    })
    .to_string();

    let envelope_json = serde_json::json!({
        "v": 2,
        "curve": "ed25519",
        "share": BASE64.encode(mat_json.as_bytes()),
    })
    .to_string();

    Ok(BASE64.encode(envelope_json.as_bytes()))
}

// ── Key material inner struct ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Ed25519KeyMaterial {
    kp: String,  // base64 of KeyPackage::serialize()
    pkp: String, // base64 of PublicKeyPackage::serialize()
}

fn extract_key_material(
    share: &str,
) -> Result<
    (
        frost_ed25519::keys::KeyPackage,
        frost_ed25519::keys::PublicKeyPackage,
    ),
    String,
> {
    let env = ShareEnvelope::decode(share)?;
    if env.curve != "ed25519" {
        return Err("share is not an ed25519 keyshare".to_string());
    }
    let share_bytes = BASE64
        .decode(&env.share)
        .map_err(|e| format!("base64 decode share: {e}"))?;
    let mat: Ed25519KeyMaterial = serde_json::from_slice(&share_bytes)
        .map_err(|e| format!("invalid ed25519 key material: {e}"))?;
    let kp_bytes = BASE64
        .decode(&mat.kp)
        .map_err(|e| format!("base64 decode kp: {e}"))?;
    let pkp_bytes = BASE64
        .decode(&mat.pkp)
        .map_err(|e| format!("base64 decode pkp: {e}"))?;
    let kp = frost_ed25519::keys::KeyPackage::deserialize(&kp_bytes)
        .map_err(|e| format!("deserialize KeyPackage: {e}"))?;
    let pkp = frost_ed25519::keys::PublicKeyPackage::deserialize(&pkp_bytes)
        .map_err(|e| format!("deserialize PublicKeyPackage: {e}"))?;
    Ok((kp, pkp))
}

// ── export_private_key ────────────────────────────────────────────────────────

/// Reconstruct the ed25519 secret scalar from two 2-of-2 FROST keyshares
/// using Lagrange interpolation at x=0.
///
/// Both `local_share` and `server_share` must be ShareEnvelope v2 base64 strings
/// as produced by `build_share_envelope`.
///
/// Returns `ExportResult` with the 32-byte scalar as a 64-char hex string.
/// The scalar is the FROST secret scalar, not an RFC 8032 seed.
pub fn export_private_key(local_share: &str, server_share: &str) -> Result<ExportResult, String> {
    let (local_kp, local_pkp) = extract_key_material(local_share)?;
    let (server_kp, server_pkp) = extract_key_material(server_share)?;

    // Both shares must reference the same verifying_key.
    let local_vk = local_pkp
        .verifying_key()
        .serialize()
        .map_err(|e| format!("verifying_key serialize: {e}"))?;
    let server_vk = server_pkp
        .verifying_key()
        .serialize()
        .map_err(|e| format!("verifying_key serialize: {e}"))?;
    if local_vk != server_vk {
        return Err("export failed: verifying_key mismatch between local and server share".to_string());
    }

    // Identifier bytes and signing share bytes.
    let local_id_bytes = local_kp.identifier().serialize();
    let server_id_bytes = server_kp.identifier().serialize();
    let local_s_bytes = local_kp.signing_share().serialize();
    let server_s_bytes = server_kp.signing_share().serialize();

    fn to_scalar(bytes: &[u8], label: &str) -> Result<Scalar, String> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{label}: expected 32 bytes, got {}", bytes.len()))?;
        Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
            .ok_or_else(|| format!("{label}: not a canonical mod-q scalar"))
    }

    let x1 = to_scalar(&local_id_bytes, "local identifier")?;
    let x2 = to_scalar(&server_id_bytes, "server identifier")?;
    let s1 = to_scalar(&local_s_bytes, "local signing_share")?;
    let s2 = to_scalar(&server_s_bytes, "server signing_share")?;

    // Lagrange coefficients at x=0 for 2-of-2:
    //   L1(0) = (0 - x2) / (x1 - x2) = -x2 * (x1 - x2)^-1
    //   L2(0) = (0 - x1) / (x2 - x1) = -x1 * (x2 - x1)^-1
    let diff = x1 - x2;
    if diff == Scalar::ZERO {
        return Err("export failed: identical identifiers".to_string());
    }
    let l1 = (-x2) * diff.invert();
    let l2 = (-x1) * (-diff).invert();
    let secret = l1 * s1 + l2 * s2;

    // Defensive check: secret * G must equal verifying_key.
    let derived = (&secret * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    if derived.as_slice() != local_vk.as_slice() {
        return Err(
            "export failed: reconstructed scalar does not match verifying_key".to_string(),
        );
    }

    Ok(ExportResult {
        private_key: hex::encode(secret.to_bytes()),
        exported: true,
    })
}
