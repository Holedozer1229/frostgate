//! Key-path spend construction for the federation's P2TR UTXO.
//!
//! Flow:
//! 1. [`build_spend`] assembles the unsigned transaction spending the
//!    federation UTXO to a destination address.
//! 2. [`key_spend_sighash`] computes the BIP341 sighash for input 0 — this
//!    32-byte digest is the *message* for the FROST signing session
//!    ([`frostgate_federation::signing::OperatorSigner::sign_with_tweak`]
//!    with `merkle_root = None`).
//! 3. [`attach_signature`] places the aggregated 64-byte Schnorr signature in
//!    the witness (no sighash byte appended: `TapSighashType::Default`).
//!
//! The resulting transaction is consensus-valid: the offline test verifies
//! the witness signature with `rust-bitcoin`'s Schnorr verifier against the
//! tweaked output key, and D3's regtest run broadcasts a real one.

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighash};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use frostgate_federation::signing::Coordinator;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpendError {
    #[error("taproot error: {0}")]
    Taproot(#[from] super::taproot::TaprootError),
    #[error("sighash error: {0}")]
    Sighash(#[from] bitcoin::sighash::TaprootError),
    #[error("address error: {0}")]
    Address(#[from] bitcoin::address::FromScriptError),
    #[error("bad input: {0}")]
    Input(String),
    #[error("secp256k1 error: {0}")]
    Secp(#[from] bitcoin::secp256k1::Error),
}

/// A federation UTXO to spend.
#[derive(Debug, Clone)]
pub struct FederationUtxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: Amount,
}

/// Build the unsigned key-path spend: federation UTXO -> `dest`, minus `fee`.
pub fn build_spend(
    utxo: &FederationUtxo,
    federation_script_pubkey: ScriptBuf,
    dest: &Address<NetworkUnchecked>,
    fee: Amount,
    network: Network,
) -> Result<(Transaction, TxOut), SpendError> {
    let dest = dest
        .clone()
        .require_network(network)
        .map_err(|e| SpendError::Input(format!("destination address network mismatch: {e}")))?;
    let out_value = utxo
        .value
        .checked_sub(fee)
        .ok_or_else(|| SpendError::Input("fee exceeds input value".to_string()))?;
    let prevout = TxOut {
        value: utxo.value,
        script_pubkey: federation_script_pubkey,
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(utxo.txid, utxo.vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: out_value,
            script_pubkey: dest.script_pubkey(),
        }],
    };
    Ok((tx, prevout))
}

/// BIP341 key-spend sighash for input 0. The returned 32 bytes are the FROST
/// signing message.
pub fn key_spend_sighash(tx: &Transaction, prevout: &TxOut) -> Result<[u8; 32], SpendError> {
    let mut cache = SighashCache::new(tx);
    let sighash: TapSighash = cache.taproot_key_spend_signature_hash(
        0,
        &Prevouts::All(std::slice::from_ref(prevout)),
        TapSighashType::Default,
    )?;
    Ok(sighash.to_byte_array())
}

/// Attach the aggregated threshold signature as the input witness.
pub fn attach_signature(tx: &mut Transaction, signature_bytes: &[u8]) -> Result<(), SpendError> {
    if signature_bytes.len() != 64 {
        return Err(SpendError::Input(format!(
            "BIP340 signature must be 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    tx.input[0].witness = Witness::from_slice(&[signature_bytes]);
    Ok(())
}

/// Verify the attached witness signature with `rust-bitcoin`'s Schnorr
/// verifier against the federation's tweaked output key — an independent,
/// consensus-shaped check that the FROST signature is a valid Taproot
/// key-path signature for this transaction.
pub fn verify_witness(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    tx: &Transaction,
    prevout: &TxOut,
    coord: &Coordinator,
) -> Result<(), SpendError> {
    use bitcoin::secp256k1::{schnorr, Message};

    let tweaked: XOnlyPublicKey = super::tweaked_output_key(coord)?;
    let sighash = key_spend_sighash(tx, prevout)?;
    let msg = Message::from_digest(sighash);
    let witness = &tx.input[0].witness;
    if witness.len() != 1 || witness[0].len() != 64 {
        return Err(SpendError::Input(
            "expected a single 64-byte witness item".to_string(),
        ));
    }
    let sig = schnorr::Signature::from_slice(&witness[0])?;
    secp.verify_schnorr(&sig, &msg, &tweaked)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot::federation_address;
    use frostgate_federation::{run_dkg, CeremonyConfig, Coordinator, OperatorSigner};
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    /// Full offline threshold spend: DKG -> P2TR -> build tx -> sighash ->
    /// FROST sign_with_tweak -> aggregate_with_tweak -> attach -> verify with
    /// rust-bitcoin Schnorr (consensus-shaped check), plus frost verify.
    #[test]
    fn offline_threshold_spend_verifies_with_rust_bitcoin() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        let coord = Coordinator::new(ops[0].public_key_package.clone());

        // Federation address and its scriptPubKey.
        let fed_addr = federation_address(&coord, Network::Regtest).unwrap();
        let fed_spk = fed_addr.script_pubkey();

        // Fake-but-well-formed funding UTXO (offline: no chain needed for the
        // sighash/signing math).
        let utxo = FederationUtxo {
            txid: Txid::from_str(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            vout: 0,
            value: Amount::from_sat(1_000_000),
        };
        let dest = Address::from_str("bcrt1qehslyy6k3t8zmgsd8nvc99easlr34usl26elvl").unwrap();
        let (mut tx, prevout) = build_spend(
            &utxo,
            fed_spk,
            &dest,
            Amount::from_sat(500),
            Network::Regtest,
        )
        .unwrap();

        // Sighash is the FROST message.
        let sighash = key_spend_sighash(&tx, &prevout).unwrap();

        // 3-of-5 FROST session with the Taproot tweak.
        let mut signers: Vec<OperatorSigner> =
            ops.into_iter().take(3).map(OperatorSigner::new).collect();
        let mut commitments = BTreeMap::new();
        for s in signers.iter_mut() {
            commitments.insert(s.identifier(), s.commit(&mut OsRng).unwrap());
        }
        let package = coord.build_package(commitments, &sighash).unwrap();
        let mut shares = BTreeMap::new();
        for s in signers.iter_mut() {
            shares.insert(s.identifier(), s.sign_with_tweak(&package, None).unwrap());
        }
        let sig = coord.aggregate_with_tweak(&package, &shares, None).unwrap();

        // Frost-level check under the tweaked key.
        coord.verify_with_tweak(&sighash, &sig, None).unwrap();

        // Attach and verify with rust-bitcoin (consensus-shaped).
        let sig_bytes = Coordinator::signature_bytes(&sig).unwrap();
        attach_signature(&mut tx, &sig_bytes).unwrap();
        verify_witness(&secp, &tx, &prevout, &coord).unwrap();
    }

    #[test]
    fn build_spend_rejects_wrong_network_dest() {
        let utxo = FederationUtxo {
            txid: Txid::from_str(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            vout: 0,
            value: Amount::from_sat(1000),
        };
        // Mainnet address against a regtest spend.
        let dest = Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        let spk = ScriptBuf::new(); // scriptPubKey content is irrelevant to the network check
        assert!(build_spend(&utxo, spk, &dest, Amount::from_sat(100), Network::Regtest).is_err());
    }
}
