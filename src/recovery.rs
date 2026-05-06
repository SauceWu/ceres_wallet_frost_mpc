//! FROST-Ed25519 key refresh: 3-round recovery, party-agnostic.

use std::collections::BTreeMap;

use frost_ed25519::keys::dkg::{round1 as dkg_r1, round2 as dkg_r2};
use frost_ed25519::keys::refresh;
use frost_ed25519::Identifier;

use crate::error::FrostMpcError;
use crate::wire::{decode_inner, encode_inner, frost_ser, RefreshR1Payload, RefreshR2Payload};

const MAX_SIGNERS: u16 = 2;
const MIN_SIGNERS: u16 = 2;

/// State held between recovery rounds.
pub struct RecoverySessionState {
    pub my_id: Identifier,
    pub other_id: Identifier,
    pub r1_secret: Option<dkg_r1::SecretPackage>,
    pub old_key_pkg: frost_ed25519::keys::KeyPackage,
    pub old_pub_key_pkg: frost_ed25519::keys::PublicKeyPackage,
    pub other_r1_pkg: Option<dkg_r1::Package>,
    pub r2_secret: Option<dkg_r2::SecretPackage>,
}

/// Round 1: own identifier is derived from `key_pkg`;
/// the other party's identifier is inferred as the complement in {1, 2}.
pub fn recovery_part1(
    key_pkg: frost_ed25519::keys::KeyPackage,
    pub_key_pkg: frost_ed25519::keys::PublicKeyPackage,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<(RecoverySessionState, String), FrostMpcError> {
    let my_id = *key_pkg.identifier();
    let other_id = complement(my_id)?;
    let (r1_secret, r1_pkg) =
        refresh::refresh_dkg_part1(my_id, MAX_SIGNERS, MIN_SIGNERS, rng)
            .map_err(|e| FrostMpcError::Protocol(format!("refresh_dkg_part1: {e}")))?;
    let payload = RefreshR1Payload {
        refresh_round1_pkg: frost_ser!(&r1_pkg, "refresh_r1_pkg")?,
    };
    let encoded = encode_inner(&payload)?;
    Ok((
        RecoverySessionState {
            my_id,
            other_id,
            r1_secret: Some(r1_secret),
            old_key_pkg: key_pkg,
            old_pub_key_pkg: pub_key_pkg,
            other_r1_pkg: None,
            r2_secret: None,
        },
        encoded,
    ))
}

/// Round 2: receive other party's r1 encoded, return `(updated_state, own_r2_encoded)`.
pub fn recovery_part2(
    mut state: RecoverySessionState,
    other_r1_encoded: &str,
) -> Result<(RecoverySessionState, String), FrostMpcError> {
    let inner: RefreshR1Payload = decode_inner(other_r1_encoded)?;
    let other_r1_pkg = dkg_r1::Package::deserialize(
        &hex::decode(&inner.refresh_round1_pkg)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode refresh r1: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize refresh r1: {e}")))?;

    let r1_secret = state
        .r1_secret
        .take()
        .ok_or_else(|| FrostMpcError::Protocol("r1_secret already consumed".to_string()))?;

    let mut r1_pkgs = BTreeMap::new();
    r1_pkgs.insert(state.other_id, other_r1_pkg.clone());

    let (r2_secret, r2_pkgs) = refresh::refresh_dkg_part2(r1_secret, &r1_pkgs)
        .map_err(|e| FrostMpcError::Protocol(format!("refresh_dkg_part2: {e}")))?;

    let r2_for_other = r2_pkgs
        .get(&state.other_id)
        .ok_or_else(|| FrostMpcError::Protocol("no r2 pkg for other party in refresh".to_string()))?
        .clone();

    let payload = RefreshR2Payload {
        refresh_round2_pkg: frost_ser!(&r2_for_other, "refresh_r2_pkg")?,
    };
    let encoded = encode_inner(&payload)?;

    state.other_r1_pkg = Some(other_r1_pkg);
    state.r2_secret = Some(r2_secret);
    Ok((state, encoded))
}

/// Round 3: receive other party's r2 encoded, finalize key refresh.
/// Returns `(new_KeyPackage, new_PublicKeyPackage)`.
pub fn recovery_part3(
    state: RecoverySessionState,
    other_r2_encoded: &str,
) -> Result<
    (
        frost_ed25519::keys::KeyPackage,
        frost_ed25519::keys::PublicKeyPackage,
    ),
    FrostMpcError,
> {
    let inner: RefreshR2Payload = decode_inner(other_r2_encoded)?;
    let other_r2_pkg = dkg_r2::Package::deserialize(
        &hex::decode(&inner.refresh_round2_pkg)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode refresh r2: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize refresh r2: {e}")))?;

    let r2_secret = state
        .r2_secret
        .ok_or_else(|| FrostMpcError::Protocol("r2_secret missing".to_string()))?;
    let other_r1_pkg = state
        .other_r1_pkg
        .ok_or_else(|| FrostMpcError::Protocol("other_r1_pkg missing for finalize".to_string()))?;

    let mut r1_pkgs = BTreeMap::new();
    r1_pkgs.insert(state.other_id, other_r1_pkg);
    let mut r2_pkgs = BTreeMap::new();
    r2_pkgs.insert(state.other_id, other_r2_pkg);

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

fn complement(my_id: Identifier) -> Result<Identifier, FrostMpcError> {
    let id1 = id(1)?;
    let id2 = id(2)?;
    if my_id == id1 {
        Ok(id2)
    } else if my_id == id2 {
        Ok(id1)
    } else {
        Err(FrostMpcError::Protocol(
            "party_id must be 1 or 2 in a 2-of-2 scheme".to_string(),
        ))
    }
}
