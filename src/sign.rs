//! FROST-Ed25519 signing: 2-round sign, party-agnostic coordinator.

use std::collections::BTreeMap;

use frost_ed25519::{round1 as sign_r1, round2 as sign_r2, Identifier, SigningPackage};

use crate::error::FrostMpcError;
use crate::wire::{decode_inner, encode_inner, frost_ser, SignR1Payload, SignR2Payload};

/// State held between sign round 1 and round 2.
pub struct SignSessionState {
    pub nonces: sign_r1::SigningNonces,
    pub my_commitments: sign_r1::SigningCommitments,
    pub message_hash: [u8; 32],
    pub my_id: Identifier,
    pub other_id: Identifier,
}

/// Round 1: commit. Own identifier is derived from `key_package`; `other_party_id`
/// identifies the other participant.
pub fn sign_part1(
    key_package: &frost_ed25519::keys::KeyPackage,
    other_party_id: u16,
    message_hash: [u8; 32],
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<(SignSessionState, String), FrostMpcError> {
    let my_id = *key_package.identifier();
    let other_id = id(other_party_id)?;
    let (nonces, my_commitments) = sign_r1::commit(key_package.signing_share(), rng);
    let payload = SignR1Payload {
        commitments: frost_ser!(&my_commitments, "my_commitments")?,
    };
    let encoded = encode_inner(&payload)?;
    Ok((SignSessionState { nonces, my_commitments, message_hash, my_id, other_id }, encoded))
}

/// Round 2 (coordinator): receive other party's commitments, produce signing package + own sig share.
pub fn sign_part2(
    state: SignSessionState,
    other_commitments_encoded: &str,
    key_package: &frost_ed25519::keys::KeyPackage,
) -> Result<String, FrostMpcError> {
    let inner: SignR1Payload = decode_inner(other_commitments_encoded)?;
    let other_commitments = sign_r1::SigningCommitments::deserialize(
        &hex::decode(&inner.commitments)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode other commitments: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize other commitments: {e}")))?;

    let mut commitments_map = BTreeMap::new();
    commitments_map.insert(state.my_id, state.my_commitments);
    commitments_map.insert(state.other_id, other_commitments);

    let signing_package = SigningPackage::new(commitments_map, &state.message_hash);
    let sig_share = sign_r2::sign(&signing_package, &state.nonces, key_package)
        .map_err(|e| FrostMpcError::Protocol(format!("FROST sign: {e}")))?;

    let payload = SignR2Payload {
        signing_pkg: frost_ser!(&signing_package, "signing_pkg")?,
        sig_share: hex::encode(sig_share.serialize()),
    };
    encode_inner(&payload)
}

fn id(n: u16) -> Result<Identifier, FrostMpcError> {
    Identifier::try_from(n).map_err(|e| FrostMpcError::Protocol(format!("Identifier({n}): {e}")))
}
