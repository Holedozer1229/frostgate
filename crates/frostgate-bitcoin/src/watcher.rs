//! Esplora peg-in watcher.
//!
//! Polls an Esplora HTTP API for UTXOs paying the federation's P2TR address
//! on Bitcoin testnet3. The coordinator (D5) turns each new confirmed UTXO
//! into a signing session whose attestation releases ZEC on the Zcash leg.
//!
//! Default endpoint: `https://blockstream.info/testnet/api` (no key needed).

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WatcherError {
    // Boxed: ureq::Error is ~272 bytes; returning it inline makes every
    // Result<_, WatcherError> pay for the large Err variant (clippy::result_large_err).
    #[error("http error: {0}")]
    Http(Box<ureq::Error>),
    #[error("json error: {0}")]
    Json(#[from] std::io::Error),
    #[error("api error: {0}")]
    Api(String),
}

impl From<ureq::Error> for WatcherError {
    fn from(e: ureq::Error) -> Self {
        Self::Http(Box::new(e))
    }
}

/// A UTXO paying the watched address, as reported by Esplora.
#[derive(Debug, Clone, Deserialize)]
pub struct EsploraUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
}

/// Build a ureq agent that honors the standard proxy env vars
/// (`HTTPS_PROXY`/`https_proxy`, falling back to `ALL_PROXY`/`all_proxy`).
/// The sandbox egress requires an explicit CONNECT proxy; without this,
/// direct TLS handshakes are transparently intercepted and fail.
fn agent() -> Result<ureq::Agent, WatcherError> {
    let mut builder = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20));
    let proxy_url = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .or_else(|_| std::env::var("ALL_PROXY"))
        .or_else(|_| std::env::var("all_proxy"));
    if let Ok(url) = proxy_url {
        let proxy = ureq::Proxy::new(url)?;
        builder = builder.proxy(proxy);
    }
    Ok(builder.build())
}

/// All UTXOs currently paying `address` (confirmed and mempool).
pub fn address_utxos(esplora_base: &str, address: &str) -> Result<Vec<EsploraUtxo>, WatcherError> {
    let url = format!(
        "{}/address/{}/utxo",
        esplora_base.trim_end_matches('/'),
        address
    );
    let resp = agent()?.get(&url).call()?;
    let utxos: Vec<EsploraUtxo> = resp.into_json()?;
    Ok(utxos)
}

/// Peg-in candidates: confirmed UTXOs only, oldest first. Mempool (unconfirmed)
/// outputs are not actionable — the coordinator must not attest to a peg-in
/// that can still be replaced.
pub fn peg_in_utxos(esplora_base: &str, address: &str) -> Result<Vec<EsploraUtxo>, WatcherError> {
    let mut utxos = address_utxos(esplora_base, address)?;
    utxos.retain(|u| u.status.confirmed);
    utxos.sort_by_key(|u| u.status.block_height.unwrap_or(u32::MAX));
    Ok(utxos)
}

/// Blockstream's public testnet3 Esplora.
pub const BLOCKSTREAM_TESTNET: &str = "https://blockstream.info/testnet/api";

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"[
        {
            "txid": "f4184fc596403b9d638783cf57adfe4c75c605f635f677169930b8258838b8",
            "vout": 0,
            "value": 100000,
            "status": {
                "confirmed": true,
                "block_height": 123456,
                "block_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "block_time": 1727740800
            }
        },
        {
            "txid": "e4184fc596403b9d638783cf57adfe4c75c605f635f677169930b8258838b7",
            "vout": 1,
            "value": 50000,
            "status": {
                "confirmed": false,
                "block_height": null,
                "block_hash": null,
                "block_time": null
            }
        }
    ]"#;

    #[test]
    fn watcher_parses_esplora_utxo_fixture() {
        let utxos: Vec<EsploraUtxo> = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(utxos.len(), 2);
        assert!(utxos[0].status.confirmed);
        assert_eq!(utxos[0].status.block_height, Some(123456));
        assert!(!utxos[1].status.confirmed);
    }

    #[test]
    fn peg_in_filtering_keeps_confirmed_only() {
        let utxos: Vec<EsploraUtxo> = serde_json::from_str(FIXTURE).unwrap();
        let mut confirmed = utxos.clone();
        confirmed.retain(|u| u.status.confirmed);
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].value, 100_000);
    }

    /// Live smoke test against Blockstream testnet3 Esplora. Ignored by
    /// default (network + external service); run with
    /// `cargo test -- --ignored` for a real end-to-end watcher check.
    #[test]
    #[ignore]
    fn live_esplora_testnet3_smoke() {
        // BIP173 test-vector program encoded with the tb1 HRP (checksum
        // verified locally); zero balance is fine — the smoke test proves
        // reachability and JSON parsing, returning an empty UTXO list.
        let utxos = address_utxos(
            BLOCKSTREAM_TESTNET,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        )
        .unwrap();
        // Must at least parse; balance may be zero.
        let _ = utxos;
    }
}
