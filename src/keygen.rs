//! FROST-Ed25519 DKG: 3-round keygen, party-agnostic.

use std::collections::BTreeMap;

use frost_ed25519::keys::dkg;
use frost_ed25519::keys::dkg::{round1 as dkg_r1, round2 as dkg_r2};
use frost_ed25519::Identifier;

use crate::error::FrostMpcError;
use crate::wire::{decode_inner, encode_inner, frost_ser, DkgR1Payload, DkgR2Payload};

const MAX_SIGNERS: u16 = 2;
const MIN_SIGNERS: u16 = 2;

/// State held between rounds (stored by the caller, e.g. in a session map).
pub struct KeygenSessionState {
    pub my_id: Identifier,
    pub other_id: Identifier,
    pub r1_secret: Option<dkg_r1::SecretPackage>,
    pub r1_pkg: dkg_r1::Package,
    pub other_r1_pkg: Option<dkg_r1::Package>,
    pub r2_secret: Option<dkg_r2::SecretPackage>,
}

/// Round 1: generate own DKG round-1 package.
/// `party_id` is this party's numeric identifier (1 or 2); the other party's id is inferred.
pub fn keygen_part1(
    party_id: u16,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<(KeygenSessionState, String), FrostMpcError> {
    let my_id = id(party_id)?;
    let other_id = complement(my_id)?;
    let (r1_secret, r1_pkg) = dkg::part1(my_id, MAX_SIGNERS, MIN_SIGNERS, rng)
        .map_err(|e| FrostMpcError::Protocol(format!("dkg::part1: {e}")))?;
    let payload = DkgR1Payload { round1_pkg: frost_ser!(&r1_pkg, "r1_pkg")? };
    let encoded = encode_inner(&payload)?;
    Ok((
        KeygenSessionState {
            my_id,
            other_id,
            r1_secret: Some(r1_secret),
            r1_pkg,
            other_r1_pkg: None,
            r2_secret: None,
        },
        encoded,
    ))
}

/// Round 2: receive other party's r1 encoded, return `(updated_state, own_r2_encoded)`.
pub fn keygen_part2(
    mut state: KeygenSessionState,
    other_r1_encoded: &str,
) -> Result<(KeygenSessionState, String), FrostMpcError> {
    let inner: DkgR1Payload = decode_inner(other_r1_encoded)?;
    let other_r1_pkg = dkg_r1::Package::deserialize(
        &hex::decode(&inner.round1_pkg)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode other r1_pkg: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize other r1_pkg: {e}")))?;

    let r1_secret = state
        .r1_secret
        .take()
        .ok_or_else(|| FrostMpcError::Protocol("r1_secret already consumed".to_string()))?;

    let mut r1_pkgs = BTreeMap::new();
    r1_pkgs.insert(state.other_id, other_r1_pkg.clone());

    let (r2_secret, r2_pkgs) = dkg::part2(r1_secret, &r1_pkgs)
        .map_err(|e| FrostMpcError::Protocol(format!("dkg::part2: {e}")))?;

    let r2_for_other = r2_pkgs
        .get(&state.other_id)
        .ok_or_else(|| FrostMpcError::Protocol("no r2 pkg for other party".to_string()))?
        .clone();

    let payload = DkgR2Payload { round2_pkg: frost_ser!(&r2_for_other, "r2_pkg")? };
    let encoded = encode_inner(&payload)?;

    state.other_r1_pkg = Some(other_r1_pkg);
    state.r2_secret = Some(r2_secret);
    Ok((state, encoded))
}

/// Round 3: receive other party's r2 encoded, finalize DKG.
/// Returns `(KeyPackage, PublicKeyPackage)`.
pub fn keygen_part3(
    state: KeygenSessionState,
    other_r2_encoded: &str,
) -> Result<
    (
        frost_ed25519::keys::KeyPackage,
        frost_ed25519::keys::PublicKeyPackage,
    ),
    FrostMpcError,
> {
    let inner: DkgR2Payload = decode_inner(other_r2_encoded)?;
    let other_r2_pkg = dkg_r2::Package::deserialize(
        &hex::decode(&inner.round2_pkg)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode other r2_pkg: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize other r2_pkg: {e}")))?;

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

    dkg::part3(&r2_secret, &r1_pkgs, &r2_pkgs)
        .map_err(|e| FrostMpcError::Protocol(format!("dkg::part3: {e}")))
}

fn id(n: u16) -> Result<Identifier, FrostMpcError> {
    Identifier::try_from(n).map_err(|e| FrostMpcError::Protocol(format!("Identifier({n}): {e}")))
}

/// In a 2-of-2 scheme with identifiers {1, 2}, return the other party's identifier.
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
