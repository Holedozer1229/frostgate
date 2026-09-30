//! `frostgate-coordinator` CLI.
//!
//! - `demo`: full in-process D5/D6 demo — fresh ceremony, mock Zcash chain,
//!   synthetic peg-in, settle, printed transcript. Fault injection via
//!   `--fault` makes the D6 adversarial cases demo-runnable.
//! - `watch`: live coordinator loop — Esplora peg-in scan against a
//!   persisted ceremony, real Zcash JSON-RPC for the release leg. Needs a
//!   funded vault; without TAZ it reports "vault not funded" and settles
//!   nothing (honest, not silent).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use frostgate_coordinator::{
    CoordinatorService, Journal, OperatorRelay, PegIn, RelayFault, ServiceConfig,
};
use frostgate_zcash::client::{ChainClient, MockChain, ZcashRpc};
use frostgate_zcash::keys::ReleaseKey;
use rand::rngs::OsRng;

#[derive(Parser)]
#[command(name = "frostgate-coordinator", about = "Frostgate bridge coordinator")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// In-process end-to-end demo: DKG -> mock peg-in -> FROST session ->
    /// mock ZEC release, with a printed transcript.
    Demo {
        /// Fault to inject: none | offline:1,2 | malicious:2
        #[arg(long, default_value = "none")]
        fault: String,
        /// Synthetic peg-in value in sats.
        #[arg(long, default_value_t = 50_000_000)]
        pegin_sats: u64,
    },
    /// Live coordinator loop: scan Esplora testnet3 for peg-ins to the
    /// federation address, settle each through the FROST quorum, broadcast
    /// the ZEC release via Zcash JSON-RPC.
    Watch(Box<WatchArgs>),
}

/// Watch-mode arguments, boxed because the variant is much larger than `Demo`.
#[derive(clap::Args)]
struct WatchArgs {
    /// Ceremony directory (from `frostgate-operator dkg`).
    #[arg(long, default_value = "ceremony")]
    ceremony: PathBuf,
    /// Esplora base URL.
    #[arg(long, default_value = "https://blockstream.info/testnet/api")]
    esplora: String,
    /// Zcash JSON-RPC URL (testnet).
    #[arg(long)]
    zcash_rpc_url: String,
    #[arg(long)]
    zcash_rpc_user: String,
    #[arg(long)]
    zcash_rpc_pass: String,
    /// Coordinator release-key file (from the zcash keygen step).
    #[arg(long)]
    release_key: PathBuf,
    /// Vault funding outpoint (display txid).
    #[arg(long)]
    vault_txid: String,
    /// Vault funding vout.
    #[arg(long)]
    vault_vout: u32,
    /// ZEC release destination (testnet tm… address).
    #[arg(long)]
    dest: String,
    /// Journal file for replay protection.
    #[arg(long, default_value = "coordinator-journal.json")]
    journal: PathBuf,
    /// Poll interval in seconds.
    #[arg(long, default_value_t = 60)]
    interval_secs: u64,
    /// Simulate offline operators (comma-separated 1-based indices).
    #[arg(long, default_value = "")]
    offline: String,
}

fn parse_fault(s: &str) -> Result<RelayFault> {
    if s == "none" {
        return Ok(RelayFault::none());
    }
    if let Some(ids) = s.strip_prefix("offline:") {
        let v: Vec<u16> = ids
            .split(',')
            .map(|x| {
                x.trim()
                    .parse::<u16>()
                    .with_context(|| format!("bad id: {x}"))
            })
            .collect::<Result<_>>()?;
        return Ok(RelayFault::none().offline(&v));
    }
    if let Some(id) = s.strip_prefix("malicious:") {
        let v: u16 = id.trim().parse().with_context(|| format!("bad id: {id}"))?;
        return Ok(RelayFault::none().corrupt_share(v));
    }
    anyhow::bail!("unknown fault '{s}' (want none | offline:1,2 | malicious:2)")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Demo { fault, pegin_sats } => demo(&parse_fault(&fault)?, pegin_sats),
        Cmd::Watch(w) => watch(&w),
    }
}

fn demo(fault: &RelayFault, pegin_sats: u64) -> Result<()> {
    use frostgate_federation::{group_key_hex, run_dkg, CeremonyConfig, Coordinator};

    println!("=== Frostgate coordinator demo ===");
    println!("fault injection: {fault:?}");
    println!();
    println!("TRUST MODEL (demo relay signs what the coordinator hands it;");
    println!("production operators must verify the attestation before signing).");
    println!();

    // ---- Ceremony ----
    let config = CeremonyConfig::new(5, 3)?;
    let ops = run_dkg(config, OsRng).context("DKG failed")?;
    let group_pkg = ops[0].public_key_package.clone();
    println!("DKG complete: 5 operators, threshold 3");
    println!("group key: {}", group_key_hex(&group_pkg)?);

    let coord = Coordinator::new(group_pkg.clone());
    let fed_addr = frostgate_bitcoin::federation_address(&coord, bitcoin::Network::Testnet)?;
    println!("federation P2TR (testnet): {fed_addr}");

    // ---- Best-effort live scan (real watcher code, may lack network) ----
    match frostgate_bitcoin::watcher::peg_in_utxos(
        "https://blockstream.info/testnet/api",
        &fed_addr.to_string(),
    ) {
        Ok(utxos) => println!("live Esplora scan: {} confirmed peg-in(s)", utxos.len()),
        Err(e) => println!("live Esplora scan unavailable ({e}); using synthetic peg-in"),
    }

    // ---- Mock Zcash leg ----
    let mut chain = MockChain {
        height: 2_900_000,
        ..Default::default()
    };
    let release_key = ReleaseKey::generate(&mut OsRng)?;
    let pkh = frostgate_zcash::address::hash160_of_pubkey(&release_key.public_key_compressed());
    let vault_script = frostgate_zcash::address::p2pkh_script_pubkey(&pkh).to_vec();
    let vault_txid = "ab".repeat(32);
    chain.fund(&vault_txid, 0, 100_000_000, &hex_encode(&vault_script));
    println!("mock vault funded: {vault_txid}:0 = 100_000_000 zat");

    let dest_key = ReleaseKey::generate(&mut OsRng)?;
    let dest_addr = frostgate_zcash::address::p2pkh_testnet(&dest_key.public_key_compressed());
    println!("release destination: {dest_addr}");

    // ---- Settle ----
    let relay = OperatorRelay::from_operators(ops, fault.clone())?;
    let cfg = ServiceConfig::demo(dest_addr.clone(), vault_txid, 0);
    let mut svc = CoordinatorService::new(group_pkg, 5, 3, relay, chain, release_key, cfg)?;

    let pegin = PegIn {
        txid_display: "cd".repeat(32),
        vout: 0,
        sats: pegin_sats,
    };
    println!();
    println!(
        "peg-in: {}:{} ({} sats)",
        pegin.txid_display, pegin.vout, pegin.sats
    );
    let rep = svc.settle(&pegin).context("settlement failed")?;

    println!();
    println!("--- settlement report ---");
    println!(
        "attestation message: {}",
        rep.attestation.attestation.message_hex()?
    );
    println!("quorum signers: {:?}", rep.signers);
    if rep.excluded_cheaters.is_empty() {
        println!("excluded cheaters: none");
    } else {
        println!(
            "EXCLUDED CHEATERS (bad share detected + attributed): {:?}",
            rep.excluded_cheaters
        );
    }
    println!("release: {} zat to {dest_addr}", rep.release_zat);
    println!("toll: {} zat (30 bps)", rep.toll_zat);
    println!("ZEC release txid (mock broadcast): {}", rep.release_txid);
    println!(
        "journal: {} settlement(s), replay of this peg-in now refused",
        svc.journal().settled_count()
    );
    // Prove the replay refusal loudly.
    match svc.settle(&pegin) {
        Ok(_) => println!("WARNING: double-settle accepted (BUG)"),
        Err(e) => println!("replay check: second settle refused ({e})"),
    }
    Ok(())
}

fn watch(w: &WatchArgs) -> Result<()> {
    use frostgate_federation::{load_group, load_operator, Coordinator};

    let ceremony = &w.ceremony;
    let group_pkg = load_group(ceremony).context("load group.json")?;
    let group_file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ceremony.join("group.json"))?)?;
    let n = group_file
        .get("num_operators")
        .and_then(serde_json::Value::as_u64)
        .context("group.json missing num_operators")? as u16;
    let t = group_file
        .get("threshold")
        .and_then(serde_json::Value::as_u64)
        .context("group.json missing threshold")? as usize;

    let offline_ids: Vec<u16> = if w.offline.is_empty() {
        Vec::new()
    } else {
        w.offline
            .split(',')
            .map(|x| {
                x.trim()
                    .parse::<u16>()
                    .with_context(|| format!("bad id: {x}"))
            })
            .collect::<Result<_>>()?
    };
    let mut ops = Vec::new();
    for i in 1..=n {
        ops.push(load_operator(ceremony, i).context("load operator key")?);
    }
    let relay = OperatorRelay::from_operators(ops, RelayFault::none().offline(&offline_ids))?;

    let chain = ZcashRpc::new(&w.zcash_rpc_url, &w.zcash_rpc_user, &w.zcash_rpc_pass);
    let tip = chain.height().context("zcash RPC unreachable")?;
    println!("zcash tip: {tip}");

    let release_key = ReleaseKey::load(&w.release_key).context("load release key")?;
    let mut config = ServiceConfig::demo(w.dest.clone(), w.vault_txid.clone(), w.vault_vout);
    config.esplora_base = w.esplora.clone();
    let mut svc = CoordinatorService::new(group_pkg, n, t, relay, chain, release_key, config)?;

    if w.journal.exists() {
        svc.set_journal(Journal::load(&w.journal).context("load journal")?);
        println!(
            "journal: {} prior settlement(s)",
            svc.journal().settled_count()
        );
    }

    let coord = Coordinator::new(frostgate_federation::load_group(ceremony)?);
    let fed_addr = frostgate_bitcoin::federation_address(&coord, bitcoin::Network::Testnet)?;
    println!("watching {fed_addr} for peg-ins (threshold {t}-of-{n})...");

    loop {
        match svc.scan_pegins(&fed_addr.to_string()) {
            Ok(pegins) => {
                for pegin in pegins {
                    println!(
                        "new peg-in: {}:{} ({} sats)",
                        pegin.txid_display, pegin.vout, pegin.sats
                    );
                    match svc.settle(&pegin) {
                        Ok(rep) => {
                            println!(
                                "settled: signers={:?} cheaters={:?} release_txid={}",
                                rep.signers, rep.excluded_cheaters, rep.release_txid
                            );
                            if let Err(e) = svc.journal().save(&w.journal) {
                                println!("WARNING: journal save failed: {e}");
                            }
                        }
                        Err(e) => println!("settlement failed: {e}"),
                    }
                }
            }
            Err(e) => println!("scan failed: {e}"),
        }
        std::thread::sleep(Duration::from_secs(w.interval_secs));
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
