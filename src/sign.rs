//! FROST-Ed25519 signing: 2-round sign coordinator (server = Identifier 2).

use std::collections::BTreeMap;

use frost_ed25519::{round1 as sign_r1, round2 as sign_r2, Identifier, SigningPackage};

use crate::error::FrostMpcError;
use crate::wire::{decode_inner, encode_inner, frost_ser, SignR1Payload, SignR2Payload};

const CLIENT_ID: u16 = 1;
const SERVER_ID: u16 = 2;

/// State held between sign round 1 and round 2.
pub struct SignSessionState {
    pub nonces: sign_r1::SigningNonces,
    pub server_commitments: sign_r1::SigningCommitments,
    pub message_hash: [u8; 32],
}

/// Round 1: server commits (no client input).
/// Returns `(state, server_commitments_encoded)`.
pub fn sign_part1(
    key_package: &frost_ed25519::keys::KeyPackage,
    message_hash: [u8; 32],
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<(SignSessionState, String), FrostMpcError> {
    let (nonces, server_commitments) =
        sign_r1::commit(key_package.signing_share(), rng);
    let payload = SignR1Payload {
        commitments: frost_ser!(&server_commitments, "server_commitments")?,
    };
    let encoded = encode_inner(&payload)?;
    Ok((SignSessionState { nonces, server_commitments, message_hash }, encoded))
}

/// Round 2: receive client commitments encoded, return `{signing_pkg, sig_share}` encoded.
pub fn sign_part2(
    state: SignSessionState,
    client_commitments_encoded: &str,
    key_package: &frost_ed25519::keys::KeyPackage,
) -> Result<String, FrostMpcError> {
    let inner: SignR1Payload = decode_inner(client_commitments_encoded)?;
    let client_commitments = sign_r1::SigningCommitments::deserialize(
        &hex::decode(&inner.commitments)
            .map_err(|e| FrostMpcError::InvalidInput(format!("hex decode client commitments: {e}")))?,
    )
    .map_err(|e| FrostMpcError::InvalidInput(format!("deserialize client commitments: {e}")))?;

    let client_id = id(CLIENT_ID)?;
    let server_id = id(SERVER_ID)?;
    let mut commitments_map = BTreeMap::new();
    commitments_map.insert(client_id, client_commitments);
    commitments_map.insert(server_id, state.server_commitments);

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

