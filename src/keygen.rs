//! FROST-Ed25519 DKG: 3-round keygen (server = Identifier 2).

use std::collections::BTreeMap;

use frost_ed25519::keys::dkg;
use frost_ed25519::keys::dkg::{round1 as dkg_r1, round2 as dkg_r2};
use frost_ed25519::Identifier;

use crate::error::FrostMpcError;
use crate::wire::{decode_inner, encode_inner, frost_ser, DkgR1Payload, DkgR2Payload};

const CLIENT_ID: u16 = 1;
const SERVER_ID: u16 = 2;
const MAX_SIGNERS: u16 = 2;
const MIN_SIGNERS: u16 = 2;

/// State held between rounds (stored by the caller, e.g. in a session map).
pub struct KeygenSessionState {
    pub r1_secret: Option<dkg_r1::SecretPackage>,  // consumed by part2
    pub r1_pkg: dkg_r1::Package,
    pub client_r1_pkg: Option<dkg_r1::Package>,
    pub r2_secret: Option<dkg_r2::SecretPackage>,
}

/// Round 1: server generates r1 independently.
/// Returns `(state, server_r1_encoded)` where `server_r1_encoded` is base64(json) for WireEnvelope.payload.
pub fn keygen_part1(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<(KeygenSessionState, String), FrostMpcError> {
    let server_id = id(SERVER_ID)?;
    let (r1_secret, r1_pkg) = dkg::part1(server_id, MAX_SIGNERS, MIN_SIGNERS, rng)
        .map_err(|e| FrostMpcError::Protocol(format!("dkg::part1: {e}")))?;
    let payload = DkgR1Payload { round1_pkg: frost_ser!(&r1_pkg, "r1_pkg")? };
    let encoded = encode_inner(&payload)?;
    Ok((KeygenSessionState { r1_secret: Some(r1_secret), r1_pkg, client_r1_pkg: None, r2_secret: None }, encoded))
}

/// Round 2: receive client r1 encoded payload, return `(updated_state, server_r2_encoded)`.
pub fn keygen_part2(
    mut state: KeygenSessionState,
    client_r1_encoded: &str,
) -> Result<(KeygenSessionState, String), FrostMpcError> {
    let inner: DkgR1Payload = decode_inner(client_r1_encoded)?;
    let client_r1_pkg = dkg_r1::Package::deserialize(
        &hex::decode(&inner.round1_pkg)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode client r1_pkg: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize client r1_pkg: {e}")))?;

    let r1_secret = state
        .r1_secret
        .take()
        .ok_or_else(|| FrostMpcError::Protocol("r1_secret already consumed".to_string()))?;

    let client_id = id(CLIENT_ID)?;
    let mut r1_pkgs = BTreeMap::new();
    r1_pkgs.insert(client_id, client_r1_pkg.clone());

    let (r2_secret, r2_pkgs) = dkg::part2(r1_secret, &r1_pkgs)
        .map_err(|e| FrostMpcError::Protocol(format!("dkg::part2: {e}")))?;

    let r2_for_client = r2_pkgs
        .get(&client_id)
        .ok_or_else(|| FrostMpcError::Protocol("no r2 pkg for client".to_string()))?
        .clone();

    let payload = DkgR2Payload { round2_pkg: frost_ser!(&r2_for_client, "r2_pkg")? };
    let encoded = encode_inner(&payload)?;

    state.client_r1_pkg = Some(client_r1_pkg);
    state.r2_secret = Some(r2_secret);
    // r1_secret was consumed by dkg::part2; overwrite with a placeholder to prevent reuse.
    // (Safe because state.r1_secret was moved into dkg::part2.)
    Ok((state, encoded))
}

/// Round 3: receive client r2 encoded payload, finalize DKG.
/// Returns `(KeyPackage, PublicKeyPackage)`.
pub fn keygen_part3(
    state: KeygenSessionState,
    client_r2_encoded: &str,
) -> Result<
    (
        frost_ed25519::keys::KeyPackage,
        frost_ed25519::keys::PublicKeyPackage,
    ),
    FrostMpcError,
> {
    let inner: DkgR2Payload = decode_inner(client_r2_encoded)?;
    let client_r2_pkg = dkg_r2::Package::deserialize(
        &hex::decode(&inner.round2_pkg)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode client r2_pkg: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize client r2_pkg: {e}")))?;

    let r2_secret = state
        .r2_secret
        .ok_or_else(|| FrostMpcError::Protocol("r2_secret missing".to_string()))?;
    let client_r1_pkg = state
        .client_r1_pkg
        .ok_or_else(|| FrostMpcError::Protocol("client_r1_pkg missing for finalize".to_string()))?;

    let client_id = id(CLIENT_ID)?;
    let mut r1_pkgs = BTreeMap::new();
    r1_pkgs.insert(client_id, client_r1_pkg);
    let mut r2_pkgs = BTreeMap::new();
    r2_pkgs.insert(client_id, client_r2_pkg);

    dkg::part3(&r2_secret, &r1_pkgs, &r2_pkgs)
        .map_err(|e| FrostMpcError::Protocol(format!("dkg::part3: {e}")))
}

fn id(n: u16) -> Result<Identifier, FrostMpcError> {
    Identifier::try_from(n).map_err(|e| FrostMpcError::Protocol(format!("Identifier({n}): {e}")))
}

