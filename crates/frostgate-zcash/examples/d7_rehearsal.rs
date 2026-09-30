//! D7 testnet rehearsal: build + sign the ZEC release spending the faucet UTXO.
//!
//! Prints the signed raw tx hex (for broadcast) and its txid.
//! Run from the workspace root:
//!   cargo run -p frostgate-zcash --example d7_rehearsal

use std::path::Path;

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::SecretKey;
use frostgate_zcash::address::{p2pkh_script_pubkey, p2pkh_testnet, parse_p2pkh_testnet};
use frostgate_zcash::keys::{hex_encode, ReleaseKey};
use frostgate_zcash::tx::{build_release, txid_from_display, txid_to_display, OutPoint};

fn main() {
    // --- Vault funding: faucet UTXO (from zcashfaucet.jinolabs.xyz receipt) ---
    let faucet_txid_display = "c92cb7e4834c47876a0cba4e6b28e25f747c24ec5c9127549f6aa07a045baf8b";
    let faucet_vout: u32 = 0;
    let faucet_value_zat: u64 = 10_000_000; // 0.1 TAZ

    // --- Load the coordinator release key (vault key) ---
    let key_path = Path::new("rehearsal/release-key.json");
    let key = ReleaseKey::load(key_path).expect("load release key");
    let secret = SecretKey::from_slice(&key.secret_bytes()).expect("secret");
    let vault_addr = p2pkh_testnet(&key.public_key_compressed());
    let vault_pkh = parse_p2pkh_testnet(&vault_addr).expect("parse vault addr");
    let vault_script = p2pkh_script_pubkey(&vault_pkh).to_vec();

    // --- Release destination (fresh user address, generated for D7) ---
    let dest_addr = "tmMyJsXk8gup34svHq8SegVUHcNxjaMB7rU";
    let dest_pkh = parse_p2pkh_testnet(dest_addr).expect("parse dest addr");
    let dest_script = p2pkh_script_pubkey(&dest_pkh).to_vec();

    // --- Amounts: release 0.09 TAZ, change back to vault, 10k zat fee ---
    let release_zat: u64 = 9_000_000;
    // expiry must exceed the live tip (lightwalletd reported 4419986 on 2026-09-30);
    // tip + ~5000 blocks (~4 days) of buffer.
    let expiry_height: u32 = 4_425_000;

    let outpoint = OutPoint {
        txid: txid_from_display(faucet_txid_display).expect("parse faucet txid"),
        vout: faucet_vout,
    };
    let inputs = vec![(outpoint, faucet_value_zat, vault_script.clone())];

    // Consensus branch ID for testnet (from lightwalletd GetLightdInfo, 2026-09-30)
    const BRANCH_ID: u32 = 0x37A5165B;
    let signed = build_release(
        &secret,
        &inputs,
        dest_script,
        vault_script,
        release_zat,
        expiry_height,
        BRANCH_ID,
    )
    .expect("build_release");

    let raw = signed.serialize().expect("serialize");
    let txid_bytes: [u8; 32] = sha256d::Hash::hash(&raw).to_byte_array();

    println!("vault:   {vault_addr}");
    println!("dest:    {dest_addr}");
    println!(
        "release: {release_zat} zat, fee: 10000 zat, change: {} zat",
        faucet_value_zat - release_zat - 10_000
    );
    println!("txid:    {}", txid_to_display(&txid_bytes));
    println!("raw_hex: {}", hex_encode(&raw));
}
