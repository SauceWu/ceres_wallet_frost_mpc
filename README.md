# ceres_wallet_frost_mpc

FROST-Ed25519 2-of-2 threshold signing library for Solana MPC wallets.

Pure cryptographic primitives — no session management, no async runtime, no network layer. The integration layer lives in the application that consumes this crate.

This library is the Ed25519/Solana counterpart of [dkls23](https://github.com/silence-laboratories/dkls23): same feature set, different algorithm.

[中文文档](README.zh.md)

## Features

| Feature | Description |
|---------|-------------|
| **Keygen** | 3-round Distributed Key Generation (FROST DKG) |
| **Sign** | 2-round threshold signing (FROST signature) |
| **Recovery** | 3-round key refresh — rotates shares without changing the verifying key |
| **Export** | Lagrange 2-of-2 scalar reconstruction to recover the raw Ed25519 private key |
| **Backup** | AES-256-GCM + HKDF-SHA256 encryption of keyshares for secure backup |

## Protocol

2-of-2 threshold scheme. Both parties must participate in every operation.

- Client: `Identifier(1)`
- Server: `Identifier(2)`

Round functions are pure — they take inputs, return outputs, and leave session state management to the caller.

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
ceres_wallet_frost_mpc = { git = "https://github.com/SauceWu/ceres_wallet_frost_mpc.git" }
```

### Key Generation (3 rounds)

```rust
use ceres_wallet_frost_mpc::{keygen_part1, keygen_part2, keygen_part3};

// Server round 1 — no client input needed
let (state, srv_r1_encoded) = keygen_part1(&mut rng)?;

// Server round 2 — receive client's round 1 message
let (state, srv_r2_encoded) = keygen_part2(state, &client_r1_encoded)?;

// Server round 3 — receive client's round 2 message, produce key packages
let (key_package, public_key_package) = keygen_part3(state, &client_r2_encoded)?;
```

### Signing (2 rounds)

```rust
use ceres_wallet_frost_mpc::{sign_part1, sign_part2};

// Server round 1 — commit
let (state, srv_r1_encoded) = sign_part1(&key_package, message_hash, &mut rng)?;

// Server round 2 — receive client commitments, produce signing package + sig share
let srv_r2_encoded = sign_part2(state, &client_r1_encoded, &key_package)?;
// Client aggregates both sig shares to produce the final Schnorr signature
```

### Key Recovery / Share Rotation (3 rounds)

```rust
use ceres_wallet_frost_mpc::{recovery_part1, recovery_part2, recovery_part3};

let (state, srv_r1_encoded) = recovery_part1(key_package, public_key_package, &mut rng)?;
let (state, srv_r2_encoded) = recovery_part2(state, &client_r1_encoded)?;
let (new_key_package, new_public_key_package) = recovery_part3(state, &client_r2_encoded)?;
// Verifying key is unchanged — only the shares rotate
```

### Key Export

Reconstructs the raw Ed25519 secret scalar from both shares using Lagrange interpolation.

```rust
use ceres_wallet_frost_mpc::{build_share_envelope, export_private_key};

let local_share = build_share_envelope(&client_key_package, &public_key_package)?;
let server_share = build_share_envelope(&server_key_package, &public_key_package)?;

let result = export_private_key(&local_share, &server_share)?;
// result.private_key — 64-char hex string (32-byte Ed25519 scalar)
// result.exported    — true
```

### Backup

```rust
use ceres_wallet_frost_mpc::{derive_backup_envelope, decrypt_backup_share};

let backup = derive_backup_envelope(&share_envelope, "user-secret", "2026-01-01")?;
let recovered = decrypt_backup_share(&backup, "user-secret")?;
```

## Wire Format

Round functions exchange opaque `base64(json({...}))` strings. Field names are protocol-stable:

| Round | Fields |
|-------|--------|
| keygen r1 | `round1_pkg` (hex) |
| keygen r2 | `round2_pkg` (hex) |
| recovery r1 | `refresh_round1_pkg` (hex) |
| recovery r2 | `refresh_round2_pkg` (hex) |
| sign r1 | `commitments` (hex) |
| sign r2 | `signing_pkg` (hex), `sig_share` (hex) |

ShareEnvelope v2 format:
```
base64( json({ "v": 2, "curve": "ed25519", "share": base64( json({ "kp": base64(...), "pkp": base64(...) }) ) }) )
```

## Security Notes

- `export_private_key` performs a defensive check: `scalar × G == verifying_key`. Returns an error if the reconstructed key does not match.
- Backup uses a random 12-byte nonce per call; repeated encryption of the same share produces different ciphertexts.
- HKDF info string: `ceres-mpc-backup-v1`.
- This library does not enforce the "export once" guard — the caller is responsible for that policy.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `frost-ed25519` v3 | FROST threshold signing protocol |
| `curve25519-dalek` v4 | Ed25519 scalar arithmetic for key export |
| `aes-gcm` | AES-256-GCM backup encryption |
| `hkdf` + `sha2` | Key derivation for backup |
| `serde` + `serde_json` | Payload serialization |
| `base64` + `hex` | Wire encoding |
| `rand` | Nonce and randomness |

## License

MIT
