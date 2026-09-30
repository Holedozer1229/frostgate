//! Bitcoin leg of the Frostgate threshold federation bridge.
//!
//! - [`taproot`]: derive the federation's P2TR key-path address from the
//!   FROST group key (single source of truth: the ZF `-tr` crate's BIP341
//!   tweak; cross-checked byte-for-byte against `rust-bitcoin` in tests).
//! - [`spend`]: build an unsigned key-path spend, compute its sighash, and
//!   attach a FROST threshold signature as the witness.
//! - [`watcher`]: Esplora peg-in watcher — lists confirmed UTXOs paying the
//!   federation address on Bitcoin testnet3.

pub mod spend;
pub mod taproot;
pub mod watcher;

pub use taproot::{federation_address, tweaked_output_key};
pub use watcher::{peg_in_utxos, EsploraUtxo};
