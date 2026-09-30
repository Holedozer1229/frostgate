//! Frostgate coordinator service: the pipeline that turns a confirmed
//! Bitcoin peg-in into a ZEC release.
//!
//! Pipeline (see [`service::CoordinatorService`]):
//! 1. [`frostgate_bitcoin::watcher`] finds confirmed UTXOs paying the
//!    federation's P2TR address on Bitcoin testnet3.
//! 2. The coordinator builds a [`frostgate_zcash::attest::ReleaseAttestation`]
//!    and runs a 3-of-5 FROST signing session through the [`relay`].
//! 3. The quorum-signed attestation authorizes [`service`] to build and
//!    broadcast the Zcash release transaction via a [`frostgate_zcash::client::ChainClient`].
//!
//! # Trust model (read this before deploying)
//! - **Coordinator is trusted for liveness, not for custody of the FROST
//!   key.** The coordinator never holds FROST secret shares; if it goes
//!   down, settlements halt and funds stay locked in the federation P2TR —
//!   they are not stolen, they are frozen.
//! - **Coordinator can equivocate.** It builds the `SigningPackage` and could
//!   show different messages to different signers. Production operators must
//!   therefore verify the attestation contents (destination, amounts, peg-in
//!   outpoint, nonce freshness, expiry) *before* emitting a share — the
//!   [`relay::OperatorRelay`] signs what it is given, which is honest for a
//!   demo relay and explicitly NOT the production posture.
//! - **ZEC execution is 1-of-1.** The release vault is a coordinator-held hot
//!   key; the 3-of-5 quorum controls *authorization* (the signed
//!   attestation), not execution. A malicious coordinator could broadcast a
//!   release that differs from the attested one — but the attestation is
//!   publicly verifiable, so the deviation is attributable after the fact.
//!   Accountability, not prevention, is the mechanism here; the code says so
//!   plainly.
//! - **Fresh nonces every session.** Enforced structurally by
//!   [`frostgate_federation::OperatorSigner`]: a commitment pair is
//!   single-use and consumed by signing.
//! - **Replay protection.** The [`journal::Journal`] rejects an already-
//!   settled peg-in outpoint and refuses to reuse an attestation nonce.
//!
//! # Audit-scope honesty
//! Built on the Zcash Foundation's FROST implementation (`frost-core` was
//! NCC-assessed; `frost-secp256k1-tr` was explicitly outside that scope).
//! Never "audited".

pub mod journal;
pub mod relay;
pub mod service;

pub use journal::Journal;
pub use relay::{OperatorRelay, RelayFault};
pub use service::{CoordinatorService, PegIn, ServiceConfig, SettlementReport};
