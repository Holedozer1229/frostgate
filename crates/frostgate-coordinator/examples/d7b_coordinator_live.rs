//! D7b live rehearsal: the FULL coordinator path against Zcash testnet.
//!
//! Fresh 5-of-3 DKG -> [`OperatorRelay`] -> [`CoordinatorService::settle`]
//! -> lightwalletd broadcast on testnet.zec.rocks. The peg-in is a labeled
//! SYNTHETIC rehearsal peg-in (the BTC peg-in leg was proven on regtest;
//! what this exercises is the FROST quorum attestation -> ZEC release ->
//! live node acceptance path, which the D7 direct `build_release` call
//! skipped).
//!
//! Run from the workspace root:
//!   cargo run -p frostgate-coordinator --example d7b_coordinator_live
//!
//! Requirements: python3 + curl on PATH, network access to
//! testnet.zec.rocks:443, and a funded coordinator vault (the D7 change
//! UTXO). Broadcasts a REAL testnet transaction.

use std::path::{Path, PathBuf};
use std::process::Command;

use bitcoin::hashes::{sha256, Hash};
use frostgate_coordinator::{CoordinatorService, OperatorRelay, PegIn, RelayFault, ServiceConfig};
use frostgate_federation::{run_dkg, CeremonyConfig};
use frostgate_zcash::address::p2pkh_testnet;
use frostgate_zcash::client::{ChainClient, ChainUtxo, ClientError};
use frostgate_zcash::keys::{hex_encode, ReleaseKey};
use rand::rngs::OsRng;
use serde_json::Value;

/// The D7 release txid; its vout 1 (990_000 zat) is the funded vault change.
const VAULT_TXID: &str = "aa8972f2829ef07ab9efa7b636f38f83df859e9db0dfa0eca56cefdf5d785b5c";
const VAULT_VOUT: u32 = 1;

/// Rehearsal-only chain client: shells out to the `.dev` Python helpers
/// that speak lightwalletd gRPC. Not for production (no auth, no retries).
struct LwdBridge {
    dev_dir: PathBuf,
    vault_addr: String,
}

impl LwdBridge {
    fn new(dev_dir: PathBuf, vault_addr: String) -> Self {
        Self {
            dev_dir,
            vault_addr,
        }
    }

    fn query(&self, args: &[&str]) -> Result<String, ClientError> {
        let out = Command::new("python3")
            .arg(self.dev_dir.join("lwd_query.py"))
            .args(args)
            .output()
            .map_err(|e| ClientError::Transport(format!("spawn lwd_query.py: {e}")))?;
        if !out.status.success() {
            return Err(ClientError::Transport(format!(
                "lwd_query.py failed: {}",
                String::from_utf8_lossy(&out.stderr)
                    .chars()
                    .take(200)
                    .collect::<String>()
            )));
        }
        String::from_utf8(out.stdout)
            .map_err(|e| ClientError::BadResponse(format!("lwd_query.py not utf-8: {e}")))
    }

    fn parse_utxos(&self, body: &str) -> Result<Vec<(String, u32, u64, String)>, ClientError> {
        // Parses pairs of lines:
        //   txid=<hex> vout=<n> value=<v> zat height=<h>
        //   script=<hex>
        let mut out = Vec::new();
        let mut pending: Option<(String, u32, u64)> = None;
        for line in body.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("txid=") {
                // First whitespace token is the bare txid value (no key).
                let mut toks = rest.split_whitespace();
                let txid = toks.next().unwrap_or("").to_string();
                let mut vout = 0u32;
                let mut value = 0u64;
                for kv in toks {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    match k {
                        "vout" => vout = v.parse().unwrap_or(0),
                        "value" => value = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }
                pending = Some((txid, vout, value));
            } else if let Some(script) = line.strip_prefix("script=") {
                if let Some((txid, vout, value)) = pending.take() {
                    out.push((txid, vout, value, script.to_string()));
                }
            }
        }
        Ok(out)
    }
}

impl ChainClient for LwdBridge {
    fn height(&self) -> Result<u64, ClientError> {
        let body = self.query(&["--tip"])?;
        for line in body.lines() {
            if let Some(rest) = line.trim().strip_prefix("tip:") {
                for kv in rest.split_whitespace() {
                    if let Some(v) = kv.strip_prefix("height=") {
                        return v
                            .parse::<u64>()
                            .map_err(|e| ClientError::BadResponse(format!("bad tip height: {e}")));
                    }
                }
            }
        }
        Err(ClientError::BadResponse("tip line missing".to_string()))
    }

    fn get_utxo(&self, txid_display: &str, vout: u32) -> Result<Option<ChainUtxo>, ClientError> {
        let body = self.query(&["--address", &self.vault_addr])?;
        for (txid, idx, value, script) in self.parse_utxos(&body)? {
            if txid == txid_display && idx == vout {
                return Ok(Some(ChainUtxo {
                    value_zat: value,
                    script_pubkey_hex: script,
                    confirmations: 1,
                }));
            }
        }
        Ok(None)
    }

    fn broadcast(&self, tx_hex: &str) -> Result<String, ClientError> {
        let out = Command::new("python3")
            .arg(self.dev_dir.join("lwd_broadcast.py"))
            .arg(tx_hex)
            .output()
            .map_err(|e| ClientError::Transport(format!("spawn lwd_broadcast.py: {e}")))?;
        let body = String::from_utf8_lossy(&out.stdout);
        let err_body = String::from_utf8_lossy(&out.stderr);
        for line in body.lines() {
            if let Some(raw) = line.trim().strip_prefix("ACCEPTED txid=") {
                // lwd_broadcast.py prints the txid JSON-quoted; strip quotes.
                let txid = raw.trim().trim_matches('"');
                if txid.len() == 64 && txid.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Ok(txid.to_string());
                }
            }
        }
        Err(ClientError::Transport(format!(
            "broadcast not accepted (rc={:?}): stdout=[{}] stderr=[{}]",
            out.status.code(),
            body.chars().take(300).collect::<String>(),
            err_body.chars().take(300).collect::<String>(),
        )))
    }

    fn get_tx(&self, txid_display: &str) -> Result<Option<Value>, ClientError> {
        let body = self.query(&["--tx", txid_display])?;
        for line in body.lines() {
            if let Some(rest) = line.trim().strip_prefix("height=") {
                let h: i64 = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
                if h > 0 {
                    return Ok(Some(serde_json::json!({
                        "txid": txid_display,
                        "confirmations": 1,
                    })));
                }
            }
        }
        Ok(None)
    }
}

/// Locate the `.dev` helper directory from the current working directory.
fn find_dev_dir() -> anyhow::Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join(".dev").join("lwd_query.py").exists() {
            return Ok(dir.join(".dev"));
        }
        if !dir.pop() {
            anyhow::bail!("could not locate frostgate .dev/ from cwd");
        }
    }
}

fn main() -> anyhow::Result<()> {
    let dev_dir = find_dev_dir()?;
    println!("=== Frostgate D7b: live quorum settlement (testnet) ===");
    println!();

    // ---- Fresh 5-of-3 ceremony ----
    let ops = run_dkg(CeremonyConfig::new(5, 3)?, OsRng)?;
    let group_pkg = ops[0].public_key_package.clone();
    println!("DKG complete: 5 operators, threshold 3");
    let relay = OperatorRelay::from_operators(ops, RelayFault::none())?;

    // ---- Coordinator release key (vault key) ----
    let key_path = Path::new("rehearsal/release-key.json");
    let release_key = ReleaseKey::load(key_path)?;
    let vault_addr = p2pkh_testnet(&release_key.public_key_compressed());
    println!("vault: {vault_addr}");

    // ---- Live chain ----
    let chain = LwdBridge::new(dev_dir, vault_addr.clone());
    let tip = chain.height()?;
    println!("lightwalletd tip: {tip}");

    // ---- Fresh destination for this release ----
    let dest_key = ReleaseKey::generate(&mut OsRng)?;
    let dest_addr = p2pkh_testnet(&dest_key.public_key_compressed());
    println!("dest:  {dest_addr}");

    let mut cfg = ServiceConfig::demo(dest_addr.clone(), VAULT_TXID.to_string(), VAULT_VOUT);
    cfg.expiry_delta = 5000; // live buffer, same posture as D7
    let mut svc = CoordinatorService::new(group_pkg, 5, 3, relay, chain, release_key, cfg)?;

    // ---- Synthetic rehearsal peg-in (labeled; the BTC leg was proven on regtest) ----
    let pegin_txid =
        hex_encode(&sha256::Hash::hash(b"frostgate-d7b-rehearsal-pegin").to_byte_array());
    let pegin = PegIn {
        txid_display: pegin_txid,
        vout: 0,
        sats: 100_000,
    };
    println!();
    println!(
        "peg-in (SYNTHETIC REHEARSAL): {}:0 ({} sats)",
        pegin.txid_display, pegin.sats
    );
    println!("running FROST attestation + quorum signing...");

    let rep = svc.settle(&pegin)?;

    println!();
    println!("--- settlement report ---");
    println!(
        "attestation message: {}",
        rep.attestation.attestation.message_hex()?
    );
    println!("quorum signers: {:?}", rep.signers);
    println!("excluded cheaters: {:?}", rep.excluded_cheaters);
    println!("release: {} zat to {dest_addr}", rep.release_zat);
    println!("toll: {} zat (30 bps)", rep.toll_zat);
    println!("quorum signature re-verifies: (checked inside settle)");
    println!("ZEC release txid (LIVE broadcast): {}", rep.release_txid);
    println!();
    println!(
        "verify: python3 .dev/lwd_query.py --tx {}",
        rep.release_txid
    );
    Ok(())
}
