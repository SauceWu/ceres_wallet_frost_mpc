//! FROST-Ed25519 2-of-2 threshold signing library for ceres_wallet.
//!
//! Pure cryptographic primitives — no session management, no wire format.
//! Equivalent in scope to dkls23, but for Ed25519 / Solana.
//!
//! # Protocol functions
//!
//! | Protocol | Round | Function |
//! |----------|-------|----------|
//! | keygen   | 1     | keygen_part1 |
//! | keygen   | 2     | keygen_part2 |
//! | keygen   | 3     | keygen_part3 |
//! | sign     | 1     | sign_part1 |
//! | sign     | 2     | sign_part2 |
//! | recovery | 1     | recovery_part1 |
//! | recovery | 2     | recovery_part2 |
//! | recovery | 3     | recovery_part3 |

pub mod backup;
pub mod error;
pub mod export;
pub mod keygen;
pub mod recovery;
pub mod sign;
pub mod types;
pub mod wire;

pub use error::FrostMpcError;
pub use backup::{decrypt_backup_share, derive_backup_envelope};
pub use export::{build_share_envelope, export_private_key};
pub use keygen::{keygen_part1, keygen_part2, keygen_part3, KeygenSessionState};
pub use recovery::{recovery_part1, recovery_part2, recovery_part3, RecoverySessionState};
pub use sign::{sign_part1, sign_part2, SignSessionState};
pub use types::{BackupEnvelope, ExportResult, ShareEnvelope};
