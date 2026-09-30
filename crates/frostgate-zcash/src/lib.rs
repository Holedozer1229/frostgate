//! Frostgate Zcash leg: testnet transparent wallet, v4 transaction builder
//! (ZIP-143 sighash), JSON-RPC chain client, and FROST release attestation
//! format.
//!
//! # Trust model
//! The ZEC-side vault is a coordinator-held hot key; the 3-of-5 FROST quorum
//! controls *authorization* via [`attest::ReleaseAttestation`], not custody.
//! See [`keys`] for the full note. This is documented, not hidden.

pub mod address;
pub mod attest;
pub mod blake2b;
pub mod client;
pub mod keys;
pub mod tx;
