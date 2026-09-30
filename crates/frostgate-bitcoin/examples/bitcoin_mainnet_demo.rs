//! Bitcoin MAINNET demo: dealerless 3-of-5 FROST vault on real mainnet.
//!
//! This moves REAL bitcoin. Two phases:
//!
//!   Phase 1 (setup):  cargo run -p frostgate-bitcoin --example bitcoin_mainnet_demo -- <DEST_BC1_ADDRESS>
//!     - runs a fresh 5-of-3 DKG, saves operator shares to ./mainnet-vault (0600)
//!     - prints the federation's bc1p... P2TR address and exits
//!     - YOU fund that address with a small amount of your own BTC, then re-run
//!
//!   Phase 2 (spend):  same command again
//!     - discovers the funded UTXO via mempool.space
//!     - 3 operators FROST-sign the key-path spend to your dest address
//!     - DRY RUN by default: prints the signed tx hex, does NOT broadcast
//!     - add --broadcast to actually send it
//!
//! NEVER commit ./mainnet-vault (gitignored). NEVER share operator-*.json.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::{Address, Amount, Network, Txid};
use frostgate_bitcoin::spend::{attach_signature, build_spend, key_spend_sighash, FederationUtxo};
use frostgate_bitcoin::taproot::federation_address;
use frostgate_federation::{
    load_group, load_operator, run_dkg, save_ceremony, CeremonyConfig, Coordinator, OperatorSigner,
};
use rand::rngs::OsRng;

const ESPLORA: &str = "https://mempool.space/api";
const DEFAULT_FEE_SATS: u64 = 1000;

fn usage() -> ! {
    eprintln!("usage: bitcoin_mainnet_demo <DEST_BC1_ADDRESS> [--broadcast] [--fee-sats N] [--vault-dir PATH]");
    eprintln!("  Phase 1: creates ./mainnet-vault, prints the bc1p funding address, exits.");
    eprintln!("  Phase 2: spends the vault UTXO to DEST (dry run unless --broadcast).");
    std::process::exit(2);
}

fn fetch_utxos(addr: &str) -> Result<Vec<(String, u32, u64)>, String> {
    let url = format!("{ESPLORA}/address/{addr}/utxo");
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("esplora GET failed: {e}"))?;
    let v: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("esplora bad json: {e}"))?;
    let mut out = Vec::new();
    for u in v.as_array().cloned().unwrap_or_default() {
        let confirmed = u
            .get("status")
            .and_then(|s| s.get("confirmed"))
            .and_then(|c| c.as_bool())
            .unwrap_or(false);
        if !confirmed {
            continue;
        }
        let txid = u
            .get("txid")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let vout = u.get("vout").and_then(|n| n.as_u64()).unwrap_or(0) as u32;
        let value = u.get("value").and_then(|n| n.as_u64()).unwrap_or(0);
        if !txid.is_empty() && value > 0 {
            out.push((txid, vout, value));
        }
    }
    Ok(out)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        usage();
    }
    let dest_str = args[0].clone();
    let broadcast = args.iter().any(|a| a == "--broadcast");
    let fee_sats: u64 = args
        .windows(2)
        .find(|w| w[0] == "--fee-sats")
        .map(|w| w[1].parse().unwrap_or_else(|_| usage()))
        .unwrap_or(DEFAULT_FEE_SATS);
    let vault_dir: PathBuf = args
        .windows(2)
        .find(|w| w[0] == "--vault-dir")
        .map(|w| PathBuf::from(&w[1]))
        .unwrap_or_else(|| PathBuf::from("./mainnet-vault"));

    eprintln!("=== Frostgate Bitcoin MAINNET demo — real funds, real chain ===");

    // Destination must be a mainnet address; build_spend enforces the network match.
    let dest = Address::from_str(&dest_str).unwrap_or_else(|_| usage());

    if !vault_dir.join("group.json").exists() {
        // ---- Phase 1: ceremony ----
        eprintln!("[phase 1] running fresh 5-of-3 dealerless DKG...");
        let config = CeremonyConfig::new(5, 3).expect("ceremony config");
        let ops = run_dkg(config, OsRng).expect("dkg failed");
        std::fs::create_dir_all(&vault_dir).expect("mkdir vault");
        save_ceremony(&vault_dir, config, &ops).expect("save ceremony");
        let coord = Coordinator::new(ops[0].public_key_package.clone());
        let addr = federation_address(&coord, Network::Bitcoin).expect("address");
        println!();
        println!("FUND THIS MAINNET ADDRESS:");
        println!("{addr}");
        println!();
        println!(
            "Shares saved to {} (0600, gitignored — never share).",
            vault_dir.display()
        );
        println!("Send a SMALL amount of your own BTC, then re-run this command.");
        return;
    }

    // ---- Phase 2: spend ----
    let group = load_group(&vault_dir).expect("load group");
    let coord = Coordinator::new(group);
    let fed_addr = federation_address(&coord, Network::Bitcoin).expect("address");
    let fed_str = fed_addr.to_string();
    eprintln!("[phase 2] vault {fed_str}");

    eprintln!("waiting for a confirmed funding UTXO (ctrl-C to stop)...");
    let (txid_hex, vout, value) = loop {
        match fetch_utxos(&fed_str) {
            Ok(mut u) if !u.is_empty() => {
                u.sort_by_key(|&(_, _, v)| std::cmp::Reverse(v));
                break u.into_iter().next().unwrap();
            }
            Ok(_) => eprintln!("  no confirmed UTXO yet, retrying in 30s..."),
            Err(e) => eprintln!("  {e} — retrying in 30s..."),
        }
        std::thread::sleep(Duration::from_secs(30));
    };
    eprintln!("funded: {txid_hex}:{vout} = {value} sats");

    let utxo = FederationUtxo {
        txid: Txid::from_str(&txid_hex).expect("txid"),
        vout,
        value: Amount::from_sat(value),
    };
    if fee_sats * 10 > value {
        eprintln!(
            "fee {fee_sats} sats is >10% of the {value}-sat UTXO — refusing. Use --fee-sats."
        );
        std::process::exit(1);
    }
    let (mut tx, prevout) = build_spend(
        &utxo,
        fed_addr.script_pubkey(),
        &dest,
        Amount::from_sat(fee_sats),
        Network::Bitcoin,
    )
    .expect("build_spend failed (is DEST a mainnet address?)");

    let sighash = key_spend_sighash(&tx, &prevout).expect("sighash");
    let mut signers: Vec<OperatorSigner> = [1u16, 2, 3]
        .iter()
        .map(|i| OperatorSigner::new(load_operator(&vault_dir, *i).expect("load operator")))
        .collect();
    let mut commitments = BTreeMap::new();
    for s in signers.iter_mut() {
        commitments.insert(s.identifier(), s.commit(&mut OsRng).expect("commit"));
    }
    let package = coord.build_package(commitments, &sighash).expect("package");
    let mut shares = BTreeMap::new();
    for s in signers.iter_mut() {
        shares.insert(
            s.identifier(),
            s.sign_with_tweak(&package, None).expect("sign"),
        );
    }
    let sig = coord
        .aggregate_with_tweak(&package, &shares, None)
        .expect("aggregate");
    coord
        .verify_with_tweak(&sighash, &sig, None)
        .expect("quorum signature failed verification — NOT broadcasting");
    let sig_bytes = Coordinator::signature_bytes(&sig).expect("sig bytes");
    attach_signature(&mut tx, &sig_bytes).expect("attach");

    let txid = tx.compute_txid();
    let raw_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    println!();
    println!("SIGNED TX {txid}");
    println!("  in:  {txid_hex}:{vout} ({value} sats)");
    println!(
        "  out: {} ({} sats, fee {fee_sats} sats)",
        dest_str,
        value - fee_sats
    );

    if !broadcast {
        println!();
        println!("DRY RUN — not broadcast. Review the hex, then re-run with --broadcast:");
        println!("{raw_hex}");
        return;
    }
    let resp = ureq::post(&format!("{ESPLORA}/tx"))
        .set("Content-Type", "text/plain")
        .send_string(&raw_hex)
        .map_err(|e| format!("broadcast failed: {e}"))
        .expect("broadcast");
    let returned = resp.into_string().expect("txid body");
    println!("BROADCAST OK: {returned}");
    println!("https://mempool.space/tx/{returned}");
}
