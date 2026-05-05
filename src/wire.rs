//! Wire payload types for FROST protocol messages.
//!
//! Each round function returns an opaque base64(json(payload)) string.
//! Field names are protocol-stable — client compatibility depends on them.
//!
//!   keygen r1:    {"round1_pkg":         "<hex>"}
//!   keygen r2:    {"round2_pkg":         "<hex>"}
//!   recovery r1:  {"refresh_round1_pkg": "<hex>"}
//!   recovery r2:  {"refresh_round2_pkg": "<hex>"}
//!   sign r1:      {"commitments":        "<hex>"}
//!   sign r2:      {"signing_pkg":        "<hex>", "sig_share": "<hex>"}

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::FrostMpcError;

#[derive(Serialize, Deserialize)]
pub struct DkgR1Payload {
    pub round1_pkg: String,
}

#[derive(Serialize, Deserialize)]
pub struct DkgR2Payload {
    pub round2_pkg: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshR1Payload {
    pub refresh_round1_pkg: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshR2Payload {
    pub refresh_round2_pkg: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignR1Payload {
    pub commitments: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignR2Payload {
    pub signing_pkg: String,
    pub sig_share: String,
}

/// Encode inner payload as base64(json(payload)) — the value that goes into WireEnvelope.payload.
pub fn encode_inner<T: Serialize>(payload: &T) -> Result<String, FrostMpcError> {
    let json = serde_json::to_vec(payload)
        .map_err(|e| FrostMpcError::Serialization(format!("encode inner: {e}")))?;
    Ok(BASE64.encode(&json))
}

/// Decode base64(json(payload)) — the value extracted from WireEnvelope.payload.
pub fn decode_inner<T: for<'de> Deserialize<'de>>(encoded: &str) -> Result<T, FrostMpcError> {
    let bytes = BASE64
        .decode(encoded)
        .map_err(|e| FrostMpcError::InvalidInput(format!("base64 decode: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| FrostMpcError::InvalidInput(format!("json decode: {e}")))
}

/// Serialize a FROST package to hex using binary serialization.
macro_rules! frost_ser {
    ($pkg:expr, $label:literal) => {
        $pkg.serialize()
            .map(|b| hex::encode(b.as_ref() as &[u8]))
            .map_err(|e| {
                FrostMpcError::Serialization(format!(concat!("serialize ", $label, ": {}"), e))
            })
    };
}
pub(crate) use frost_ser;
