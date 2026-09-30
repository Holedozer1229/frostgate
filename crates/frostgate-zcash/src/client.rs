//! Zcash JSON-RPC chain client (testnet).
//!
//! Minimal surface the D5 coordinator needs:
//! - [`ChainClient::height`] — chain tip for expiry-height computation.
//! - [`ChainClient::get_utxo`] — confirm a funding outpoint is unspent
//!   (`gettxout`; returns value + scriptPubKey).
//! - [`ChainClient::broadcast`] — `sendrawtransaction`.
//! - [`ChainClient::get_tx`] — `getrawtransaction` (verbose) for
//!   confirmation polling.
//!
//! No wallet RPCs are used: keys are generated locally ([`crate::keys`])
//! and transactions are built locally ([`crate::tx`]). The node is a dumb
//! broadcast + query pipe, which is what keeps the trusted surface small.
//!
//! Amounts: zcashd reports ZEC as decimal JSON numbers. Conversion to
//! zatoshis is `(zec * 100_000_000).round()`; exact for all values below
//! 2^53 zatoshis (far above any testnet amount).

use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("bad response: {0}")]
    BadResponse(String),
    #[error("amount error: {0}")]
    Amount(String),
}

/// A spendable outpoint as seen by the chain.
#[derive(Debug, Clone)]
pub struct ChainUtxo {
    pub value_zat: u64,
    pub script_pubkey_hex: String,
    pub confirmations: u64,
}

/// Minimal chain interface. [`ZcashRpc`] implements it against a real node;
/// D5 tests use [`MockChain`].
pub trait ChainClient {
    fn height(&self) -> Result<u64, ClientError>;
    fn get_utxo(&self, txid_display: &str, vout: u32) -> Result<Option<ChainUtxo>, ClientError>;
    fn broadcast(&self, tx_hex: &str) -> Result<String, ClientError>;
    fn get_tx(&self, txid_display: &str) -> Result<Option<Value>, ClientError>;
}

/// JSON-RPC client over HTTP(S) with basic auth.
pub struct ZcashRpc {
    url: String,
    user: String,
    pass: String,
    agent: ureq::Agent,
}

impl ZcashRpc {
    pub fn new(url: &str, user: &str, pass: &str) -> Self {
        let agent: ureq::Agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(15))
            .timeout_read(std::time::Duration::from_secs(60))
            .build();
        Self {
            url: url.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            agent,
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "frostgate-zcash",
            "method": method,
            "params": params,
        });
        use base64::Engine;
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.user, self.pass));
        let resp = self
            .agent
            .post(&self.url)
            .set("Authorization", &format!("Basic {credentials}"))
            .send_json(body)
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let v: Value = resp
            .into_json()
            .map_err(|e| ClientError::BadResponse(format!("invalid json: {e}")))?;
        if let Some(err) = v.get("error") {
            if !err.is_null() {
                return Err(ClientError::Rpc {
                    code: err.get("code").and_then(Value::as_i64).unwrap_or(-1),
                    message: err
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                });
            }
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }
}

impl ChainClient for ZcashRpc {
    fn height(&self) -> Result<u64, ClientError> {
        let v = self.call("getblockcount", json!([]))?;
        v.as_u64()
            .ok_or_else(|| ClientError::BadResponse("getblockcount not a number".to_string()))
    }

    fn get_utxo(&self, txid_display: &str, vout: u32) -> Result<Option<ChainUtxo>, ClientError> {
        let v = self.call("gettxout", json!([txid_display, vout, true]))?;
        if v.is_null() {
            return Ok(None); // spent or unknown
        }
        let value_zec = v
            .get("value")
            .and_then(Value::as_f64)
            .ok_or_else(|| ClientError::BadResponse("gettxout.value not a number".to_string()))?;
        let value_zat = (value_zec * 100_000_000.0).round() as u64;
        if (value_zat as f64) / 100_000_000.0 - value_zec.abs() > 1e-9 && value_zec != 0.0 {
            // Sanity: round-trip check on the decimal conversion.
            return Err(ClientError::Amount(format!(
                "lossy ZEC->zat conversion for {value_zec}"
            )));
        }
        let script_hex = v
            .get("scriptPubKey")
            .and_then(|s| s.get("hex"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ClientError::BadResponse("gettxout.scriptPubKey.hex missing".to_string())
            })?
            .to_string();
        let confirmations = v.get("confirmations").and_then(Value::as_u64).unwrap_or(0);
        Ok(Some(ChainUtxo {
            value_zat,
            script_pubkey_hex: script_hex,
            confirmations,
        }))
    }

    fn broadcast(&self, tx_hex: &str) -> Result<String, ClientError> {
        let v = self.call("sendrawtransaction", json!([tx_hex]))?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ClientError::BadResponse("sendrawtransaction not a txid".to_string()))
    }

    fn get_tx(&self, txid_display: &str) -> Result<Option<Value>, ClientError> {
        match self.call("getrawtransaction", json!([txid_display, 1])) {
            Ok(v) => Ok(if v.is_null() { None } else { Some(v) }),
            Err(ClientError::Rpc { code: -5, .. }) => Ok(None), // "No such mempool or blockchain transaction"
            Err(e) => Err(e),
        }
    }
}

/// In-memory mock for D5 coordinator tests. Not for production use.
#[derive(Debug, Default)]
pub struct MockChain {
    pub height: u64,
    pub utxos: std::collections::HashMap<(String, u32), ChainUtxo>,
    pub mempool: std::cell::RefCell<Vec<String>>,
    pub fail_broadcast: bool,
}

impl MockChain {
    pub fn fund(&mut self, txid_display: &str, vout: u32, value_zat: u64, script_hex: &str) {
        self.utxos.insert(
            (txid_display.to_string(), vout),
            ChainUtxo {
                value_zat,
                script_pubkey_hex: script_hex.to_string(),
                confirmations: 6,
            },
        );
    }
}

impl ChainClient for MockChain {
    fn height(&self) -> Result<u64, ClientError> {
        Ok(self.height)
    }

    fn get_utxo(&self, txid_display: &str, vout: u32) -> Result<Option<ChainUtxo>, ClientError> {
        Ok(self.utxos.get(&(txid_display.to_string(), vout)).cloned())
    }

    fn broadcast(&self, tx_hex: &str) -> Result<String, ClientError> {
        if self.fail_broadcast {
            return Err(ClientError::Rpc {
                code: -26,
                message: "mock broadcast failure".to_string(),
            });
        }
        // Mock txid: sha256d of the raw bytes, display order.
        use bitcoin_hashes::{sha256, Hash};
        let raw = crate::keys::unhex(tx_hex)
            .map_err(|e| ClientError::BadResponse(format!("bad hex: {e}")))?;
        let h = sha256::Hash::hash(&sha256::Hash::hash(&raw).to_byte_array()).to_byte_array();
        let mut rev = h;
        rev.reverse();
        let txid = crate::keys::hex_encode(&rev);
        self.mempool.borrow_mut().push(tx_hex.to_string());
        Ok(txid)
    }

    fn get_tx(&self, txid_display: &str) -> Result<Option<Value>, ClientError> {
        // The mock only knows transactions it broadcast.
        for raw_hex in self.mempool.borrow().iter() {
            let raw = crate::keys::unhex(raw_hex).unwrap();
            use bitcoin_hashes::{sha256, Hash};
            let h = sha256::Hash::hash(&sha256::Hash::hash(&raw).to_byte_array()).to_byte_array();
            let mut rev = h;
            rev.reverse();
            if crate::keys::hex_encode(&rev) == txid_display {
                return Ok(Some(json!({"txid": txid_display, "confirmations": 0})));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_chain_fund_and_broadcast_roundtrip() {
        let mut mock = MockChain {
            height: 2_900_000,
            ..Default::default()
        };
        assert_eq!(mock.height().unwrap(), 2_900_000);
        mock.fund("aa".repeat(32).as_str(), 0, 50_000_000, "76a914");
        let utxo = mock.get_utxo(&"aa".repeat(32), 0).unwrap().unwrap();
        assert_eq!(utxo.value_zat, 50_000_000);
        assert!(mock.get_utxo(&"bb".repeat(32), 0).unwrap().is_none());

        let txid = mock.broadcast(&"00".repeat(100)).unwrap();
        assert_eq!(txid.len(), 64);
        assert!(mock.get_tx(&txid).unwrap().is_some());
        assert!(mock.get_tx(&"cc".repeat(32)).unwrap().is_none());
    }

    #[test]
    fn mock_chain_broadcast_failure() {
        let mock = MockChain {
            fail_broadcast: true,
            ..Default::default()
        };
        assert!(mock.broadcast("00").is_err());
    }

    #[test]
    fn rpc_client_construction_does_not_connect() {
        // Building the client must not touch the network.
        let _c = ZcashRpc::new("http://127.0.0.1:18232/", "user", "pass");
    }
}
