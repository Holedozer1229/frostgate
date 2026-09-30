//! Taproot federation key.
//!
//! The federation's on-chain identity is a P2TR key-path address whose
//! internal key is the FROST group verifying key and whose output key is the
//! BIP341 tweak of it:
//!
//! ```text
//! P (internal) = FROST group verifying key (x-only)
//! Q (output)   = P + H_TapTweak(P.x) * G        (no script tree)
//! address      = P2TR(Q)
//! ```
//!
//! # Single source of truth
//! The tweak is applied by the ZF `frost-secp256k1-tr` crate
//! ([`frostgate_federation::Coordinator::tweaked_public_package`]), the same
//! code that tweaks the signing shares. The address is derived from the
//! tweaked verifying key's x-only bytes. A test asserts byte-equality with
//! `rust-bitcoin`'s independent `tap_tweak` implementation, so any future
//! divergence fails loudly instead of producing an unspendable address.

use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, WitnessProgram, XOnlyPublicKey};
use frostgate_federation::signing::Coordinator;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TaprootError {
    #[error("frost error: {0}")]
    Frost(#[from] frostgate_federation::CeremonyError),
    #[error("bad key bytes: {0}")]
    Key(String),
    #[error("secp256k1 error: {0}")]
    Secp(#[from] bitcoin::secp256k1::Error),
}

/// The x-only BIP341 output key `Q` (tweaked group key), key-path only.
pub fn tweaked_output_key(coord: &Coordinator) -> Result<XOnlyPublicKey, TaprootError> {
    let tweaked = coord.tweaked_public_package(None);
    let bytes = tweaked
        .verifying_key()
        .serialize()
        .map_err(|e| TaprootError::Key(format!("verifying key serialization failed: {e}")))?;
    xonly_from_compressed(&bytes)
}

/// The federation's P2TR key-path address on `network`.
///
/// Single source of truth: the output key `Q` comes from the frost crate's
/// tweak (the same tweak the signing shares use), wrapped via
/// `dangerous_assume_tweaked` — "dangerous" only in the generic sense; here
/// the key genuinely is a BIP341-tweaked output key produced by the `-tr`
/// crate.
pub fn federation_address(coord: &Coordinator, network: Network) -> Result<Address, TaprootError> {
    let q = tweaked_output_key(coord)?;
    Ok(Address::p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(q),
        network,
    ))
}

/// Independent cross-check: `rust-bitcoin`'s Taproot tweak applied to the
/// internal key must produce the same 32-byte output key as the frost
/// crate's tweak. Used in tests; the production path above always goes
/// through the frost tweak.
pub fn bitcoin_tweaked_program(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    internal: XOnlyPublicKey,
) -> [u8; 32] {
    let program = WitnessProgram::p2tr(secp, internal, None);
    let bytes = program.program().as_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

fn xonly_from_compressed(compressed: &[u8]) -> Result<XOnlyPublicKey, TaprootError> {
    if compressed.len() != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03) {
        return Err(TaprootError::Key(format!(
            "expected 33-byte compressed point, got {} bytes",
            compressed.len()
        )));
    }
    XOnlyPublicKey::from_slice(&compressed[1..])
        .map_err(|e| TaprootError::Key(format!("x-only parse failed: {e}")))
}

// ---------------------------------------------------------------------------
// The federation crate needs to expose the frost error conversion; we do it
// here via a tiny public helper to avoid widening its API surface.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use frostgate_federation::{group_key_hex, run_dkg, CeremonyConfig};
    use rand::rngs::OsRng;

    fn test_coordinator() -> Coordinator {
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        Coordinator::new(ops[0].public_key_package.clone())
    }

    #[test]
    fn tweak_agreement_frost_vs_rust_bitcoin() {
        // THE critical cross-check: the frost crate's BIP341 tweak must equal
        // rust-bitcoin's independent tweak byte-for-byte, or the P2TR address
        // would not match the key the threshold signatures verify under.
        let secp = Secp256k1::new();
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        let pkg = ops[0].public_key_package.clone();

        // Frost path (production): tweak the package, take x-only of Q.
        let coord = Coordinator::new(pkg.clone());
        let q_frost = tweaked_output_key(&coord).unwrap();

        // Independent path: rust-bitcoin WitnessProgram over the internal key.
        let gk_hex = group_key_hex(&pkg).unwrap();
        let compressed = hex_to_bytes(&gk_hex);
        let internal = XOnlyPublicKey::from_slice(&compressed[1..]).unwrap();
        let q_bitcoin = bitcoin_tweaked_program(&secp, internal);

        assert_eq!(
            q_frost.serialize(),
            q_bitcoin,
            "frost tweak and rust-bitcoin tweak must agree byte-for-byte"
        );
    }

    #[test]
    fn p2tr_address_parses_and_is_key_path() {
        let coord = test_coordinator();
        let addr = federation_address(&coord, Network::Regtest).unwrap();
        assert!(
            addr.to_string().starts_with("bcrt1p"),
            "regtest P2TR prefix"
        );
        // Re-derive from the tweaked key: address must be a pure function of Q.
        let q = tweaked_output_key(&coord).unwrap();
        assert_eq!(
            addr,
            Address::p2tr_tweaked(
                TweakedPublicKey::dangerous_assume_tweaked(q),
                Network::Regtest
            )
        );
        // Testnet3 variant for the D5 watcher.
        let addr_t = federation_address(&coord, Network::Testnet).unwrap();
        assert!(addr_t.to_string().starts_with("tb1p"));
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
