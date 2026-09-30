//! Mainnet-params proof: the exact methods Frostgate created (dealerless DKG,
//! P2TR federation key, FROST key-path spend) work on `Network::Bitcoin` with
//! zero changes. Offline — no chain, no funds, no broadcast. If this test is
//! green, the only delta between the testnet demo and a mainnet vault is
//! configuration (network flag + mainnet Esplora endpoint), not cryptography.

use bitcoin::{Address, Amount, Network, Txid};
use frostgate_bitcoin::spend::{
    attach_signature, build_spend, key_spend_sighash, verify_witness, FederationUtxo,
};
use frostgate_bitcoin::taproot::federation_address;
use frostgate_federation::{run_dkg, CeremonyConfig, Coordinator, OperatorSigner};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::str::FromStr;

/// DKG -> mainnet P2TR address. Must be a `bc1p...` key-path address.
#[test]
fn mainnet_federation_address_is_bc1p() {
    let config = CeremonyConfig::new(5, 3).unwrap();
    let ops = run_dkg(config, OsRng).unwrap();
    let coord = Coordinator::new(ops[0].public_key_package.clone());

    let addr = federation_address(&coord, Network::Bitcoin).unwrap();
    let s = addr.to_string();
    assert!(
        s.starts_with("bc1p"),
        "expected mainnet P2TR address, got {s}"
    );
    assert_eq!(addr.to_string().len(), 62, "P2TR address length");
}

/// Full offline threshold spend on mainnet params: build tx -> sighash ->
/// 3-of-5 FROST sign_with_tweak -> aggregate -> attach -> verify with
/// rust-bitcoin Schnorr. Mirrors the regtest D3 flow exactly.
#[test]
fn mainnet_threshold_spend_verifies_offline() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let config = CeremonyConfig::new(5, 3).unwrap();
    let ops = run_dkg(config, OsRng).unwrap();
    let coord = Coordinator::new(ops[0].public_key_package.clone());

    let fed_addr = federation_address(&coord, Network::Bitcoin).unwrap();
    assert!(fed_addr.to_string().starts_with("bc1p"));
    let fed_spk = fed_addr.script_pubkey();

    // Fake-but-well-formed funding UTXO (offline: no chain needed).
    let utxo = FederationUtxo {
        txid: Txid::from_str("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
            .unwrap(),
        vout: 0,
        value: Amount::from_sat(1_000_000),
    };
    // BIP173 example mainnet P2WPKH address (also used in this crate's own tests).
    let dest = Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let (mut tx, prevout) = build_spend(
        &utxo,
        fed_spk,
        &dest,
        Amount::from_sat(1000),
        Network::Bitcoin,
    )
    .unwrap();

    let sighash = key_spend_sighash(&tx, &prevout).unwrap();

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

    coord.verify_with_tweak(&sighash, &sig, None).unwrap();

    let sig_bytes = Coordinator::signature_bytes(&sig).unwrap();
    attach_signature(&mut tx, &sig_bytes).unwrap();
    verify_witness(&secp, &tx, &prevout, &coord).unwrap();
}
