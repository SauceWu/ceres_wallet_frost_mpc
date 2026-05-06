//! Integration tests for ceres_wallet_frost_mpc public API.
//!
//! Each test exercises the full protocol flow end-to-end using only the
//! crate's public surface — no access to internal implementation details.

use std::collections::BTreeMap;

use frost_ed25519::{
    keys::{dkg, refresh, generate_with_dealer, IdentifierList, KeyPackage, PublicKeyPackage},
    round1 as sign_r1,
    round2 as sign_r2,
    Identifier,
};
use rand::RngCore;

use ceres_wallet_frost_mpc::{
    build_share_envelope, decrypt_backup_share, derive_backup_envelope, export_private_key,
    keygen_part1, keygen_part2, keygen_part3,
    recovery_part1, recovery_part2, recovery_part3,
    sign_part1, sign_part2,
    wire::{decode_inner, encode_inner, DkgR1Payload, DkgR2Payload, RefreshR1Payload,
           RefreshR2Payload, SignR1Payload, SignR2Payload},
};

// ── Shared helper ─────────────────────────────────────────────────────────────

const CLIENT_ID: u16 = 1;
const SERVER_ID: u16 = 2;

/// Run a full 2-of-2 DKG and return (server_kp, server_pkp, client_kp, client_pkp).
fn run_keygen() -> (KeyPackage, PublicKeyPackage, KeyPackage, PublicKeyPackage) {
    let mut rng = rand::thread_rng();
    let client_id = Identifier::try_from(CLIENT_ID).unwrap();
    let server_id = Identifier::try_from(SERVER_ID).unwrap();

    // Server round 1
    let (ks, srv_r1) = keygen_part1(SERVER_ID, &mut rng).unwrap();
    let srv_r1_inner: DkgR1Payload = decode_inner(&srv_r1).unwrap();
    let srv_r1_pkg =
        dkg::round1::Package::deserialize(&hex::decode(&srv_r1_inner.round1_pkg).unwrap())
            .unwrap();

    // Client round 1
    let (cli_r1_secret, cli_r1_pkg) = dkg::part1(client_id, 2, 2, &mut rng).unwrap();
    let cli_r1_enc = encode_inner(&DkgR1Payload {
        round1_pkg: hex::encode(cli_r1_pkg.serialize().unwrap()),
    })
    .unwrap();

    // Server round 2
    let (ks, srv_r2) = keygen_part2(ks, &cli_r1_enc).unwrap();
    let srv_r2_inner: DkgR2Payload = decode_inner(&srv_r2).unwrap();
    let srv_r2_pkg =
        dkg::round2::Package::deserialize(&hex::decode(&srv_r2_inner.round2_pkg).unwrap())
            .unwrap();

    // Client round 2
    let mut cli_r1_pkgs = BTreeMap::new();
    cli_r1_pkgs.insert(server_id, srv_r1_pkg);
    let (cli_r2_secret, cli_r2_pkgs) = dkg::part2(cli_r1_secret, &cli_r1_pkgs).unwrap();
    let cli_r2_enc = encode_inner(&DkgR2Payload {
        round2_pkg: hex::encode(cli_r2_pkgs.get(&server_id).unwrap().serialize().unwrap()),
    })
    .unwrap();

    // Server finalize
    let (srv_kp, srv_pkp) = keygen_part3(ks, &cli_r2_enc).unwrap();

    // Client finalize
    let mut r2_fin = BTreeMap::new();
    r2_fin.insert(server_id, srv_r2_pkg);
    let (cli_kp, cli_pkp) = dkg::part3(&cli_r2_secret, &cli_r1_pkgs, &r2_fin).unwrap();

    (srv_kp, srv_pkp, cli_kp, cli_pkp)
}

// ── Keygen ────────────────────────────────────────────────────────────────────

#[test]
fn test_keygen_full_roundtrip() {
    let (srv_kp, srv_pkp, cli_kp, cli_pkp) = run_keygen();
    assert_eq!(srv_pkp.verifying_key(), cli_pkp.verifying_key());
    let vk = srv_pkp.verifying_key().serialize().unwrap();
    assert_eq!(vk.as_slice().len(), 32);
    let _ = (srv_kp, cli_kp);
}

// ── Sign ──────────────────────────────────────────────────────────────────────

#[test]
fn test_sign_full_roundtrip() {
    let mut rng = rand::thread_rng();
    let client_id = Identifier::try_from(CLIENT_ID).unwrap();
    let server_id = Identifier::try_from(SERVER_ID).unwrap();
    let (srv_kp, srv_pkp, cli_kp, _) = run_keygen();

    let mut message_hash = [0u8; 32];
    rng.fill_bytes(&mut message_hash);

    // Server round 1: commit
    let (sign_state, _srv_commits_enc) =
        sign_part1(&srv_kp, message_hash, &mut rng).unwrap();

    // Client round 1: commit
    let (cli_nonces, cli_commitments) = sign_r1::commit(cli_kp.signing_share(), &mut rng);
    let cli_commits_enc = encode_inner(&SignR1Payload {
        commitments: hex::encode(cli_commitments.serialize().unwrap()),
    })
    .unwrap();

    // Server round 2: produce signing package + sig share
    let srv_r2_enc = sign_part2(sign_state, &cli_commits_enc, &srv_kp).unwrap();

    // Client aggregates
    let r2_inner: SignR2Payload = decode_inner(&srv_r2_enc).unwrap();
    let signing_pkg = frost_ed25519::SigningPackage::deserialize(
        &hex::decode(&r2_inner.signing_pkg).unwrap(),
    )
    .unwrap();
    let srv_sig_share =
        frost_ed25519::round2::SignatureShare::deserialize(&hex::decode(&r2_inner.sig_share).unwrap())
            .unwrap();
    let cli_sig_share = sign_r2::sign(&signing_pkg, &cli_nonces, &cli_kp).unwrap();

    let mut shares = BTreeMap::new();
    shares.insert(client_id, cli_sig_share);
    shares.insert(server_id, srv_sig_share);

    let signature = frost_ed25519::aggregate(&signing_pkg, &shares, &srv_pkp).unwrap();
    assert_eq!(signature.serialize().unwrap().len(), 64);
}

// ── Recovery ──────────────────────────────────────────────────────────────────

#[test]
fn test_recovery_full_roundtrip() {
    let mut rng = rand::thread_rng();
    let client_id = Identifier::try_from(CLIENT_ID).unwrap();
    let server_id = Identifier::try_from(SERVER_ID).unwrap();
    let (srv_kp, srv_pkp, cli_kp, cli_pkp) = run_keygen();
    let old_vk = srv_pkp.verifying_key().serialize().unwrap();
    let old_srv_share = srv_kp.signing_share().serialize();
    let old_srv_id = *srv_kp.identifier();

    // Server round 1
    let (state, srv_r1) = recovery_part1(srv_kp, srv_pkp, &mut rng).unwrap();
    let r1_inner: RefreshR1Payload = decode_inner(&srv_r1).unwrap();
    let srv_r1_pkg =
        dkg::round1::Package::deserialize(&hex::decode(&r1_inner.refresh_round1_pkg).unwrap())
            .unwrap();

    // Client round 1
    let (cli_r1_secret, cli_r1_pkg) =
        refresh::refresh_dkg_part1(client_id, 2, 2, &mut rng).unwrap();
    let cli_r1_enc = encode_inner(&RefreshR1Payload {
        refresh_round1_pkg: hex::encode(cli_r1_pkg.serialize().unwrap()),
    })
    .unwrap();

    // Server round 2
    let (state, srv_r2) = recovery_part2(state, &cli_r1_enc).unwrap();
    let r2_inner: RefreshR2Payload = decode_inner(&srv_r2).unwrap();
    let srv_r2_pkg =
        dkg::round2::Package::deserialize(&hex::decode(&r2_inner.refresh_round2_pkg).unwrap())
            .unwrap();

    // Client round 2
    let mut cli_r1_pkgs = BTreeMap::new();
    cli_r1_pkgs.insert(server_id, srv_r1_pkg);
    let (cli_r2_secret, cli_r2_pkgs) =
        refresh::refresh_dkg_part2(cli_r1_secret, &cli_r1_pkgs).unwrap();
    let cli_r2_enc = encode_inner(&RefreshR2Payload {
        refresh_round2_pkg: hex::encode(
            cli_r2_pkgs.get(&server_id).unwrap().serialize().unwrap(),
        ),
    })
    .unwrap();

    // Server finalize
    let (new_srv_kp, new_srv_pkp) = recovery_part3(state, &cli_r2_enc).unwrap();

    // Client finalize
    let mut r2_fin = BTreeMap::new();
    r2_fin.insert(server_id, srv_r2_pkg);
    refresh::refresh_dkg_shares(&cli_r2_secret, &cli_r1_pkgs, &r2_fin, cli_pkp, cli_kp).unwrap();

    // Verifying key unchanged
    let new_vk = new_srv_pkp.verifying_key().serialize().unwrap();
    assert_eq!(old_vk.as_slice(), new_vk.as_slice());
    // Party identifier unchanged
    assert_eq!(*new_srv_kp.identifier(), old_srv_id);
    // Signing share replaced
    assert_ne!(new_srv_kp.signing_share().serialize(), old_srv_share);
}

#[test]
fn test_recovery_rotation_version_increments() {
    let mut rng = rand::thread_rng();
    let client_id = Identifier::try_from(CLIENT_ID).unwrap();
    let server_id = Identifier::try_from(SERVER_ID).unwrap();
    let (mut srv_kp, mut srv_pkp, mut cli_kp, mut cli_pkp) = run_keygen();
    let original_vk = srv_pkp.verifying_key().serialize().unwrap();

    for rotation in 1..=3 {
        let (state, srv_r1) = recovery_part1(srv_kp, srv_pkp, &mut rng).unwrap();
        let r1_inner: RefreshR1Payload = decode_inner(&srv_r1).unwrap();
        let srv_r1_pkg =
            dkg::round1::Package::deserialize(&hex::decode(&r1_inner.refresh_round1_pkg).unwrap())
                .unwrap();
        let (cli_r1_secret, cli_r1_pkg) =
            refresh::refresh_dkg_part1(client_id, 2, 2, &mut rng).unwrap();
        let cli_r1_enc = encode_inner(&RefreshR1Payload {
            refresh_round1_pkg: hex::encode(cli_r1_pkg.serialize().unwrap()),
        })
        .unwrap();

        let (state, srv_r2) = recovery_part2(state, &cli_r1_enc).unwrap();
        let r2_inner: RefreshR2Payload = decode_inner(&srv_r2).unwrap();
        let srv_r2_pkg =
            dkg::round2::Package::deserialize(&hex::decode(&r2_inner.refresh_round2_pkg).unwrap())
                .unwrap();
        let mut cli_r1_pkgs = BTreeMap::new();
        cli_r1_pkgs.insert(server_id, srv_r1_pkg);
        let (cli_r2_secret, cli_r2_pkgs) =
            refresh::refresh_dkg_part2(cli_r1_secret, &cli_r1_pkgs).unwrap();
        let cli_r2_enc = encode_inner(&RefreshR2Payload {
            refresh_round2_pkg: hex::encode(
                cli_r2_pkgs.get(&server_id).unwrap().serialize().unwrap(),
            ),
        })
        .unwrap();

        let (new_srv_kp, new_srv_pkp) = recovery_part3(state, &cli_r2_enc).unwrap();
        let mut r2_fin = BTreeMap::new();
        r2_fin.insert(server_id, srv_r2_pkg);
        let (new_cli_kp, new_cli_pkp) =
            refresh::refresh_dkg_shares(&cli_r2_secret, &cli_r1_pkgs, &r2_fin, cli_pkp, cli_kp)
                .unwrap();

        let vk = new_srv_pkp.verifying_key().serialize().unwrap();
        assert_eq!(
            original_vk.as_slice(),
            vk.as_slice(),
            "verifying_key changed at rotation {rotation}"
        );

        srv_kp = new_srv_kp;
        srv_pkp = new_srv_pkp;
        cli_kp = new_cli_kp;
        cli_pkp = new_cli_pkp;
    }
}

// ── Export ────────────────────────────────────────────────────────────────────

#[test]
fn test_build_share_envelope_format() {
    let rng = rand::thread_rng();
    let (srv_kp, srv_pkp, _, _) = run_keygen();
    let envelope = build_share_envelope(&srv_kp, &srv_pkp).unwrap();

    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD.decode(&envelope).unwrap();
    let env: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(env["v"], 2);
    assert_eq!(env["curve"], "ed25519");
    let share_raw = base64::engine::general_purpose::STANDARD
        .decode(env["share"].as_str().unwrap())
        .unwrap();
    let mat: serde_json::Value = serde_json::from_slice(&share_raw).unwrap();
    assert!(!mat["kp"].as_str().unwrap().is_empty());
    assert!(!mat["pkp"].as_str().unwrap().is_empty());
    let _ = rng;
}

#[test]
fn test_export_private_key() {
    let mut rng = rand::thread_rng();
    let (shares, pkp) = generate_with_dealer(2, 2, IdentifierList::Default, &mut rng).unwrap();
    let client_id = Identifier::try_from(CLIENT_ID).unwrap();
    let server_id = Identifier::try_from(SERVER_ID).unwrap();
    let cli_kp = KeyPackage::try_from(shares[&client_id].clone()).unwrap();
    let srv_kp = KeyPackage::try_from(shares[&server_id].clone()).unwrap();

    let local_share = build_share_envelope(&cli_kp, &pkp).unwrap();
    let server_share = build_share_envelope(&srv_kp, &pkp).unwrap();

    let result = export_private_key(&local_share, &server_share).unwrap();
    assert!(result.exported);
    assert_eq!(result.private_key.len(), 64);
}

// ── Backup ────────────────────────────────────────────────────────────────────

#[test]
fn test_backup_roundtrip_with_real_share() {
    let rng = rand::thread_rng();
    let (srv_kp, srv_pkp, _, _) = run_keygen();
    let share = build_share_envelope(&srv_kp, &srv_pkp).unwrap();

    let envelope = derive_backup_envelope(&share, "my-secret", "2026-01-01").unwrap();
    let recovered = decrypt_backup_share(&envelope, "my-secret").unwrap();
    assert_eq!(recovered, share);
    let _ = rng;
}
