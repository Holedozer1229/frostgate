//! Frostgate operator CLI.
//!
//! D1: `dkg` subcommand runs the distributed key generation ceremony and
//! persists per-operator key material. No dealer is ever involved; no party
//! holds the full secret key.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use frostgate_federation::{
    group_key_hex, run_dkg, save_ceremony, CeremonyConfig, Coordinator, OperatorSigner,
};
use rand::rngs::OsRng;

#[derive(Parser)]
#[command(name = "frostgate-operator", about = "Frostgate federation operator")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the FROST DKG ceremony (no trusted dealer) and persist key material.
    Dkg {
        /// Number of operators in the federation.
        #[arg(long, default_value_t = 5)]
        operators: u16,
        /// Signing threshold.
        #[arg(long, default_value_t = 3)]
        threshold: u16,
        /// Output directory for key material.
        #[arg(long, default_value = "ceremony")]
        out: PathBuf,
    },
    /// Run a full in-process threshold signing demo: DKG, then a 3-of-5
    /// signing session over a fixed message, printing the group key and the
    /// 64-byte threshold signature. Uses fresh key material every run.
    DemoSign,
    /// Print the federation's P2TR key-path address for a ceremony dir.
    FederationAddress {
        /// Ceremony directory (from `dkg`).
        #[arg(long, default_value = "ceremony")]
        ceremony: PathBuf,
        /// Bitcoin network: regtest | testnet | mainnet.
        #[arg(long, default_value = "regtest")]
        network: String,
    },
    /// Threshold-spend a federation UTXO via FROST (key-path, Taproot).
    /// Prints the signed raw transaction hex to stdout.
    TaprootSpend {
        /// Ceremony directory (from `dkg`).
        #[arg(long, default_value = "ceremony")]
        ceremony: PathBuf,
        /// Signer operator indices, comma-separated (default 1,2,3).
        #[arg(long, default_value = "1,2,3")]
        signers: String,
        /// Funding txid (UTXO paying the federation address).
        #[arg(long)]
        prev_txid: String,
        /// Funding vout.
        #[arg(long)]
        prev_vout: u32,
        /// Funding value in sats.
        #[arg(long)]
        prev_value: u64,
        /// Destination address.
        #[arg(long)]
        dest: String,
        /// Fee in sats.
        #[arg(long, default_value_t = 500)]
        fee: u64,
        /// Bitcoin network: regtest | testnet | mainnet.
        #[arg(long, default_value = "regtest")]
        network: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Dkg {
            operators,
            threshold,
            out,
        } => {
            let config = CeremonyConfig::new(operators, threshold)?;
            println!(
                "Running FROST DKG ceremony: {operators} operators, threshold {threshold} (no dealer)..."
            );
            let ops = run_dkg(config, OsRng).context("DKG ceremony failed")?;
            save_ceremony(&out, config, &ops).context("failed to persist ceremony")?;
            let gk = group_key_hex(&ops[0].public_key_package)?;
            println!("Group verifying key: {gk}");
            println!(
                "Wrote {} operator key files + group.json to {}",
                ops.len(),
                out.display()
            );
            println!("NOTE: operator-*.json files are secret key material (mode 0600).");
            Ok(())
        }
        Cmd::DemoSign => {
            // D2 harness: full ceremony + one 3-of-5 signing session, in-process.
            let config = CeremonyConfig::new(5, 3)?;
            let ops = run_dkg(config, OsRng).context("DKG ceremony failed")?;
            let group_pkg = ops[0].public_key_package.clone();
            let gk = group_key_hex(&group_pkg)?;
            let coord = Coordinator::new(group_pkg);
            let mut signers: Vec<OperatorSigner> =
                ops.into_iter().take(3).map(OperatorSigner::new).collect();

            let message = b"frostgate-demo-sign: 3-of-5 threshold";
            let mut commitments = BTreeMap::new();
            for s in signers.iter_mut() {
                commitments.insert(s.identifier(), s.commit(&mut OsRng)?);
            }
            let package = coord.build_package(commitments, message)?;
            let mut shares = BTreeMap::new();
            for s in signers.iter_mut() {
                shares.insert(s.identifier(), s.sign(&package)?);
            }
            let sig = coord.aggregate(&package, &shares)?;
            coord.verify(message, &sig)?;

            let sig_hex: String = Coordinator::signature_bytes(&sig)?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            println!("3-of-5 threshold signature verifies under group key {gk}");
            println!("signature (64 bytes): {sig_hex}");
            Ok(())
        }
        Cmd::FederationAddress { ceremony, network } => {
            let network = parse_network(&network)?;
            let group_pkg = frostgate_federation::load_group(&ceremony)?;
            let coord = Coordinator::new(group_pkg);
            let addr = frostgate_bitcoin::federation_address(&coord, network)?;
            println!("{addr}");
            Ok(())
        }
        Cmd::TaprootSpend {
            ceremony,
            signers,
            prev_txid,
            prev_vout,
            prev_value,
            dest,
            fee,
            network,
        } => {
            use frostgate_bitcoin::spend::{
                attach_signature, build_spend, key_spend_sighash, FederationUtxo,
            };

            let network = parse_network(&network)?;
            let group_pkg = frostgate_federation::load_group(&ceremony)?;
            let coord = Coordinator::new(group_pkg);
            let fed_addr = frostgate_bitcoin::federation_address(&coord, network)?;

            let signer_idxs: Vec<u16> = signers
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse::<u16>()
                        .with_context(|| format!("bad signer index: {s}"))
                })
                .collect::<Result<_>>()?;
            if signer_idxs.is_empty() {
                anyhow::bail!("no signers given");
            }
            let mut ops: Vec<OperatorSigner> = signer_idxs
                .iter()
                .map(|i| {
                    frostgate_federation::load_operator(&ceremony, *i).map(OperatorSigner::new)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let utxo = FederationUtxo {
                txid: prev_txid.parse().context("bad prev_txid")?,
                vout: prev_vout,
                value: bitcoin::Amount::from_sat(prev_value),
            };
            let dest: bitcoin::address::Address<bitcoin::address::NetworkUnchecked> =
                dest.parse().context("bad dest address")?;
            let (mut tx, prevout) = build_spend(
                &utxo,
                fed_addr.script_pubkey(),
                &dest,
                bitcoin::Amount::from_sat(fee),
                network,
            )?;

            // The sighash is the FROST message; sign with the Taproot tweak.
            let sighash = key_spend_sighash(&tx, &prevout)?;
            let mut commitments = BTreeMap::new();
            for s in ops.iter_mut() {
                commitments.insert(s.identifier(), s.commit(&mut OsRng)?);
            }
            let package = coord.build_package(commitments, &sighash)?;
            let mut shares = BTreeMap::new();
            for s in ops.iter_mut() {
                shares.insert(s.identifier(), s.sign_with_tweak(&package, None)?);
            }
            let sig = coord.aggregate_with_tweak(&package, &shares, None)?;
            coord.verify_with_tweak(&sighash, &sig, None)?;

            let sig_bytes = Coordinator::signature_bytes(&sig)?;
            attach_signature(&mut tx, &sig_bytes)?;
            let raw = bitcoin::consensus::encode::serialize(&tx);
            println!("{}", hex_encode(&raw));
            Ok(())
        }
    }
}

fn parse_network(s: &str) -> Result<bitcoin::Network> {
    match s {
        "regtest" => Ok(bitcoin::Network::Regtest),
        "testnet" | "testnet3" => Ok(bitcoin::Network::Testnet),
        "mainnet" => Ok(bitcoin::Network::Bitcoin),
        _ => anyhow::bail!("unknown network: {s} (regtest|testnet|mainnet)"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
