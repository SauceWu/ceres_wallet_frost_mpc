//! FROST-Ed25519 key refresh: 3-round recovery (server = Identifier 2).

use std::collections::BTreeMap;

use frost_ed25519::keys::dkg::{round1 as dkg_r1, round2 as dkg_r2};
use frost_ed25519::keys::refresh;
use frost_ed25519::Identifier;

use crate::error::FrostMpcError;
use crate::wire::{decode_inner, encode_inner, frost_ser, RefreshR1Payload, RefreshR2Payload};

const CLIENT_ID: u16 = 1;
const SERVER_ID: u16 = 2;
const MAX_SIGNERS: u16 = 2;
const MIN_SIGNERS: u16 = 2;

/// State held between recovery rounds.
pub struct RecoverySessionState {
    pub r1_secret: Option<dkg_r1::SecretPackage>, // consumed by part2
    pub old_key_pkg: frost_ed25519::keys::KeyPackage,
    pub old_pub_key_pkg: frost_ed25519::keys::PublicKeyPackage,
    pub client_r1_pkg: Option<dkg_r1::Package>,
    pub r2_secret: Option<dkg_r2::SecretPackage>,
}

/// Round 1: server runs refresh_dkg_part1 independently.
/// Returns `(state, server_r1_encoded)`.
pub fn recovery_part1(
    key_pkg: frost_ed25519::keys::KeyPackage,
    pub_key_pkg: frost_ed25519::keys::PublicKeyPackage,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<(RecoverySessionState, String), FrostMpcError> {
    let server_id = id(SERVER_ID)?;
    let (r1_secret, r1_pkg) =
        refresh::refresh_dkg_part1(server_id, MAX_SIGNERS, MIN_SIGNERS, rng)
            .map_err(|e| FrostMpcError::Protocol(format!("refresh_dkg_part1: {e}")))?;
    let payload = RefreshR1Payload {
        refresh_round1_pkg: frost_ser!(&r1_pkg, "refresh_r1_pkg")?,
    };
    let encoded = encode_inner(&payload)?;
    Ok((
        RecoverySessionState {
            r1_secret: Some(r1_secret),
            old_key_pkg: key_pkg,
            old_pub_key_pkg: pub_key_pkg,
            client_r1_pkg: None,
            r2_secret: None,
        },
        encoded,
    ))
}

/// Round 2: receive client r1 encoded, return `(updated_state, server_r2_encoded)`.
pub fn recovery_part2(
    mut state: RecoverySessionState,
    client_r1_encoded: &str,
) -> Result<(RecoverySessionState, String), FrostMpcError> {
    let inner: RefreshR1Payload = decode_inner(client_r1_encoded)?;
    let client_r1_pkg = dkg_r1::Package::deserialize(
        &hex::decode(&inner.refresh_round1_pkg)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode refresh r1: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize refresh r1: {e}")))?;

    let r1_secret = state
        .r1_secret
        .take()
        .ok_or_else(|| FrostMpcError::Protocol("r1_secret already consumed".to_string()))?;

    let client_id = id(CLIENT_ID)?;
    let mut r1_pkgs = BTreeMap::new();
    r1_pkgs.insert(client_id, client_r1_pkg.clone());

    let (r2_secret, r2_pkgs) = refresh::refresh_dkg_part2(r1_secret, &r1_pkgs)
        .map_err(|e| FrostMpcError::Protocol(format!("refresh_dkg_part2: {e}")))?;

    let r2_for_client = r2_pkgs
        .get(&client_id)
        .ok_or_else(|| FrostMpcError::Protocol("no r2 pkg for client in refresh".to_string()))?
        .clone();

    let payload = RefreshR2Payload {
        refresh_round2_pkg: frost_ser!(&r2_for_client, "refresh_r2_pkg")?,
    };
    let encoded = encode_inner(&payload)?;

    state.client_r1_pkg = Some(client_r1_pkg);
    state.r2_secret = Some(r2_secret);
    Ok((state, encoded))
}

/// Round 3: receive client r2 encoded, finalize key refresh.
/// Returns `(new_KeyPackage, new_PublicKeyPackage)`.
pub fn recovery_part3(
    state: RecoverySessionState,
    client_r2_encoded: &str,
) -> Result<
    (
        frost_ed25519::keys::KeyPackage,
        frost_ed25519::keys::PublicKeyPackage,
    ),
    FrostMpcError,
> {
    let inner: RefreshR2Payload = decode_inner(client_r2_encoded)?;
    let client_r2_pkg = dkg_r2::Package::deserialize(
        &hex::decode(&inner.refresh_round2_pkg)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode refresh r2: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize refresh r2: {e}")))?;

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

    refresh::refresh_dkg_shares(
        &r2_secret,
        &r1_pkgs,
        &r2_pkgs,
        state.old_pub_key_pkg,
        state.old_key_pkg,
    )
    .map_err(|e| FrostMpcError::Protocol(format!("refresh_dkg_shares: {e}")))
}

fn id(n: u16) -> Result<Identifier, FrostMpcError> {
    Identifier::try_from(n).map_err(|e| FrostMpcError::Protocol(format!("Identifier({n}): {e}")))
}
