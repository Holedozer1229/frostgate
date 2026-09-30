//! Zcash v4 transparent transactions: build, ZIP-243 sighash, sign.
//!
//! Scope: transparent-only (P2PKH in/out). No JoinSplits, no Sapling/Orchard.
//! This is the demo release path; shielded legs are an explicit stretch goal.
//!
//! # Format references (consensus-critical — review against the spec)
//! - Zcash protocol spec §7.1: v4 transaction format. `nVersion = 0x80000004`
//!   (Overwintered flag + 4), `nVersionGroupId = 0x892F2085`.
//! - ZIP-243: sighash is BLAKE2b-256 (NOT SHA256d) with personalization
//!   "ZcashSigHash" || consensus_branch_id. SIGHASH_ALL only.
//! - Serialization order: header, vin, vout, nLockTime, nExpiryHeight,
//!   valueBalanceSapling (0), nShieldedSpend (0), nShieldedOutput (0),
//!   nJoinSplit (0).
//!
//! # Assumption flags (validated on testnet at D7)
//! 1. Empty joinsplit/shielded vectors are 32 zero bytes in the sighash
//!    preimage (per ZIP-243 spec: "Otherwise, hashJoinSplits is a uint256
//!    of 0x0000......0000").
//!    (Corrected 2026-09-30: the sighash is BLAKE2b-256, not SHA256d.
//!    An earlier SHA256d implementation was rejected by testnet with
//!    ScriptInvalid; the BLAKE2b version was accepted.)
//! 2. `scriptCode` is the prevout's scriptPubKey serialized as a CScript
//!    (compactsize length prefix + bytes).
//! 3. `hashPrevouts`/`hashSequence`/`hashOutputs` use BLAKE2b-256 with
//!    personalizations "ZcashPrevoutHash", "ZcashSequencHash",
//!    "ZcashOutputsHash" (per ZIP-243 reference implementation).
//!
//! A wrong assumption here produces an invalid signature, which testnet
//! rejects loudly — the D7 rehearsal is the ground truth, and the Python
//! cross-check (`../.dev/zip243_prototype.py`) pins the byte-level behavior.

use crate::blake2b::blake2b_256_personal;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin_hashes::{sha256, Hash};
use thiserror::Error;

use crate::keys::unhex;

#[derive(Debug, Error)]
pub enum TxError {
    #[error("invalid tx: {0}")]
    Invalid(String),
    #[error("secp256k1 error: {0}")]
    Secp(#[from] bitcoin::secp256k1::Error),
    #[error("key error: {0}")]
    Key(#[from] crate::keys::KeyError),
}

pub const VERSION: u32 = 0x80000004;
pub const VERSION_GROUP_ID: u32 = 0x892F2085;
pub const SIGHASH_ALL: u32 = 1;

/// Default release fee: 10_000 zatoshis. Generous for testnet; the demo
/// values speed over fee optimization.
pub const DEFAULT_FEE_ZAT: u64 = 10_000;

/// An outpoint. `txid` is stored in **internal** byte order (as serialized on
/// the wire); use [`txid_from_display`] / [`txid_to_display`] at boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// Display-order (reversed, as explorers show) hex -> internal bytes.
pub fn txid_from_display(hex: &str) -> Result<[u8; 32], TxError> {
    let v = unhex(hex).map_err(|e| TxError::Invalid(format!("bad txid hex: {e}")))?;
    if v.len() != 32 {
        return Err(TxError::Invalid(format!(
            "txid must be 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out.reverse();
    Ok(out)
}

/// Internal bytes -> display-order hex.
pub fn txid_to_display(txid: &[u8; 32]) -> String {
    let mut rev = *txid;
    rev.reverse();
    crate::keys::hex_encode(&rev)
}

#[derive(Debug, Clone)]
pub struct TxInput {
    pub prevout: OutPoint,
    pub sequence: u32,
}

#[derive(Debug, Clone)]
pub struct TxOutput {
    pub value_zat: u64,
    pub script_pubkey: Vec<u8>,
}

/// An unsigned v4 transparent transaction.
#[derive(Debug, Clone)]
pub struct UnsignedTx {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
    pub expiry_height: u32,
}

impl UnsignedTx {
    fn check(&self) -> Result<(), TxError> {
        if self.inputs.is_empty() {
            return Err(TxError::Invalid("tx needs at least one input".to_string()));
        }
        if self.outputs.is_empty() {
            return Err(TxError::Invalid("tx needs at least one output".to_string()));
        }
        Ok(())
    }
}

/// A fully-signed transaction, ready to broadcast.
#[derive(Debug, Clone)]
pub struct SignedTx {
    pub unsigned: UnsignedTx,
    pub script_sigs: Vec<Vec<u8>>,
}

impl SignedTx {
    /// Wire serialization (the bytes that get hashed for the txid and sent
    /// to `sendrawtransaction`).
    pub fn serialize(&self) -> Result<Vec<u8>, TxError> {
        self.unsigned.check()?;
        if self.script_sigs.len() != self.unsigned.inputs.len() {
            return Err(TxError::Invalid(
                "scriptSig count != input count".to_string(),
            ));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&VERSION_GROUP_ID.to_le_bytes());
        out.extend_from_slice(&compactsize(self.unsigned.inputs.len() as u64));
        for (inp, sig) in self.unsigned.inputs.iter().zip(self.script_sigs.iter()) {
            out.extend_from_slice(&ser_prevout(&inp.prevout));
            out.extend_from_slice(&compactsize(sig.len() as u64));
            out.extend_from_slice(sig);
            out.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        out.extend_from_slice(&compactsize(self.unsigned.outputs.len() as u64));
        for o in &self.unsigned.outputs {
            out.extend_from_slice(&ser_output(o));
        }
        out.extend_from_slice(&self.unsigned.lock_time.to_le_bytes());
        out.extend_from_slice(&self.unsigned.expiry_height.to_le_bytes());
        out.extend_from_slice(&0i64.to_le_bytes()); // valueBalanceSapling
        out.extend_from_slice(&compactsize(0)); // nShieldedSpend
        out.extend_from_slice(&compactsize(0)); // nShieldedOutput
        out.extend_from_slice(&compactsize(0)); // nJoinSplit
        Ok(out)
    }

    /// Transaction id, internal byte order.
    pub fn txid(&self) -> Result<[u8; 32], TxError> {
        Ok(sha256d(&self.serialize()?))
    }

    /// Transaction id, display order (what explorers show).
    pub fn txid_display(&self) -> Result<String, TxError> {
        Ok(txid_to_display(&self.txid()?))
    }

    /// Hex of the wire serialization (for `sendrawtransaction`).
    pub fn hex(&self) -> Result<String, TxError> {
        Ok(crate::keys::hex_encode(&self.serialize()?))
    }
}

/// ZIP-243 sighash for input `input_index` (SIGHASH_ALL).
///
/// `script_code` is the prevout's scriptPubKey; `input_value` its value in
/// zatoshis. Returns the 32-byte message to ECDSA-sign.
///
/// Uses BLAKE2b-256 per ZIP-243 (NOT SHA256d). The personalization for the
/// main digest is "ZcashSigHash" || consensus_branch_id (little-endian).
/// `consensus_branch_id` must match the network epoch of the block the tx
/// will be mined in (e.g. 0x37A5165B for testnet on 2026-09-30).
pub fn zip243_sighash(
    unsigned: &UnsignedTx,
    input_index: usize,
    script_code: &[u8],
    input_value: u64,
    consensus_branch_id: u32,
) -> Result<[u8; 32], TxError> {
    unsigned.check()?;
    if input_index >= unsigned.inputs.len() {
        return Err(TxError::Invalid("input index out of range".to_string()));
    }

    // BLAKE2b-256 helper with 16-byte personalization.
    fn b2b(person: &[u8; 16], data: &[u8]) -> [u8; 32] {
        blake2b_256_personal(person, data)
    }

    let hash_prevouts = b2b(
        b"ZcashPrevoutHash",
        &unsigned
            .inputs
            .iter()
            .flat_map(|i| ser_prevout(&i.prevout))
            .collect::<Vec<u8>>(),
    );
    let hash_sequence = b2b(
        b"ZcashSequencHash",
        &unsigned
            .inputs
            .iter()
            .flat_map(|i| i.sequence.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    let hash_outputs = b2b(
        b"ZcashOutputsHash",
        &unsigned
            .outputs
            .iter()
            .flat_map(ser_output)
            .collect::<Vec<u8>>(),
    );
    // ZIP-243: empty joinsplit/shielded vectors are 32 zero bytes.
    let zero32 = [0u8; 32];

    // Main personalization: "ZcashSigHash" (12 bytes) || branch_id LE (4 bytes).
    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZcashSigHash");
    personal[12..].copy_from_slice(&consensus_branch_id.to_le_bytes());

    let mut pre = Vec::with_capacity(300);
    pre.extend_from_slice(&VERSION.to_le_bytes());
    pre.extend_from_slice(&VERSION_GROUP_ID.to_le_bytes());
    pre.extend_from_slice(&hash_prevouts);
    pre.extend_from_slice(&hash_sequence);
    pre.extend_from_slice(&hash_outputs);
    pre.extend_from_slice(&zero32); // hashJoinSplits (none)
    pre.extend_from_slice(&zero32); // hashShieldedSpends (none)
    pre.extend_from_slice(&zero32); // hashShieldedOutputs (none)
    pre.extend_from_slice(&unsigned.lock_time.to_le_bytes());
    pre.extend_from_slice(&unsigned.expiry_height.to_le_bytes());
    pre.extend_from_slice(&0i64.to_le_bytes()); // valueBalanceSapling
    pre.extend_from_slice(&SIGHASH_ALL.to_le_bytes());
    let inp = &unsigned.inputs[input_index];
    pre.extend_from_slice(&ser_prevout(&inp.prevout));
    pre.extend_from_slice(&compactsize(script_code.len() as u64));
    pre.extend_from_slice(script_code);
    pre.extend_from_slice(&input_value.to_le_bytes());
    pre.extend_from_slice(&inp.sequence.to_le_bytes());

    Ok(b2b(&personal, &pre))
}

/// Backwards-compatible alias (ZIP-143 is the Overwinter predecessor;
/// v4 transactions use ZIP-243). Prefer [`zip243_sighash`].
#[deprecated(note = "use zip243_sighash with an explicit consensus branch id")]
pub fn zip143_sighash(
    unsigned: &UnsignedTx,
    input_index: usize,
    script_code: &[u8],
    input_value: u64,
) -> Result<[u8; 32], TxError> {
    // Overwinter branch id; only correct for pre-Sapling epochs.
    zip243_sighash(unsigned, input_index, script_code, input_value, 0x5BA81C2D)
}

/// Sign one P2PKH input. Returns the scriptSig:
/// `push(DER(sig) || SIGHASH_ALL) push(compressed pubkey)`.
///
/// `consensus_branch_id` is the network epoch's branch id (e.g. 0x37A5165B
/// for current testnet); it domain-separates the ZIP-243 sighash.
pub fn sign_p2pkh_input(
    unsigned: &UnsignedTx,
    input_index: usize,
    secret: &SecretKey,
    script_code: &[u8],
    input_value: u64,
    consensus_branch_id: u32,
) -> Result<Vec<u8>, TxError> {
    let secp = Secp256k1::new();
    let sighash = zip243_sighash(
        unsigned,
        input_index,
        script_code,
        input_value,
        consensus_branch_id,
    )?;
    let msg = Message::from_digest(sighash);
    let sig = secp.sign_ecdsa(&msg, secret);
    let mut der = sig.serialize_der().to_vec();
    der.push(SIGHASH_ALL as u8);
    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, secret).serialize();

    let mut script_sig = Vec::with_capacity(2 + der.len() + 33);
    script_sig.push(der.len() as u8);
    script_sig.extend_from_slice(&der);
    script_sig.push(33u8);
    script_sig.extend_from_slice(&pubkey);
    Ok(script_sig)
}

/// Convenience: build + sign a release transaction.
///
/// `inputs`: (outpoint, value_zat, script_pubkey of the prevout) — all must
/// be P2PKH outputs of `key`. Sends `amount_zat` to `dest_script`, returns
/// change to `change_script`. Fee is fixed at [`DEFAULT_FEE_ZAT`].
///
/// `consensus_branch_id`: the network epoch's branch id for the ZIP-243
/// sighash (e.g. 0x37A5165B for testnet on 2026-09-30).
pub fn build_release(
    key: &SecretKey,
    inputs: &[(OutPoint, u64, Vec<u8>)],
    dest_script: Vec<u8>,
    change_script: Vec<u8>,
    amount_zat: u64,
    expiry_height: u32,
    consensus_branch_id: u32,
) -> Result<SignedTx, TxError> {
    if inputs.is_empty() {
        return Err(TxError::Invalid("no inputs".to_string()));
    }
    let total_in: u64 = inputs.iter().map(|(_, v, _)| v).sum();
    let fee = DEFAULT_FEE_ZAT;
    if total_in < amount_zat + fee {
        return Err(TxError::Invalid(format!(
            "insufficient funds: in={total_in} need={} (amount+fee)",
            amount_zat + fee
        )));
    }
    let change = total_in - amount_zat - fee;

    let unsigned = UnsignedTx {
        inputs: inputs
            .iter()
            .map(|(op, _, _)| TxInput {
                prevout: op.clone(),
                sequence: 0xffffffff,
            })
            .collect(),
        outputs: {
            let mut outs = vec![TxOutput {
                value_zat: amount_zat,
                script_pubkey: dest_script,
            }];
            if change > 0 {
                outs.push(TxOutput {
                    value_zat: change,
                    script_pubkey: change_script,
                });
            }
            outs
        },
        lock_time: 0,
        expiry_height,
    };

    let mut script_sigs = Vec::new();
    for (i, (_, value, script_code)) in inputs.iter().enumerate() {
        script_sigs.push(sign_p2pkh_input(
            &unsigned,
            i,
            key,
            script_code,
            *value,
            consensus_branch_id,
        )?);
    }
    Ok(SignedTx {
        unsigned,
        script_sigs,
    })
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn sha256d(b: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(&sha256::Hash::hash(b).to_byte_array()).to_byte_array()
}

fn compactsize(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

fn ser_prevout(op: &OutPoint) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    v.extend_from_slice(&op.txid);
    v.extend_from_slice(&op.vout.to_le_bytes());
    v
}

fn ser_output(o: &TxOutput) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + o.script_pubkey.len() + 9);
    v.extend_from_slice(&o.value_zat.to_le_bytes());
    v.extend_from_slice(&compactsize(o.script_pubkey.len() as u64));
    v.extend_from_slice(&o.script_pubkey);
    v
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::address::{hash160_of_pubkey, p2pkh_script_pubkey, p2pkh_testnet};

    /// Fixture shared with ../.dev/zip143_check.py. The expected sighash was
    /// produced by the independent Python implementation.
    const FUNDING_TXID_DISPLAY: &str =
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33d";
    const EXPECTED_SIGHASH_HEX: &str =
        "361dd8e668d9637f1fd1650689a748a2b1980c2e16be25d2e7ea0fadf706cd4f";
    const EXPECTED_UNSIGNED_LEN: usize = 138;
    /// Testnet consensus branch id (from lightwalletd GetLightdInfo,
    /// 2026-09-30). Domain-separates the ZIP-243 sighash.
    const TEST_BRANCH_ID: u32 = 0x37A5165B;

    fn fixture() -> (UnsignedTx, Vec<u8>, u64) {
        let pkh = unhex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut pkh_arr = [0u8; 20];
        pkh_arr.copy_from_slice(&pkh);
        let script_pubkey = p2pkh_script_pubkey(&pkh_arr).to_vec();
        // Well-formed 20-byte destination P2PKH, mirroring the Python fixture.
        let dest_pkh: [u8; 20] = unhex("b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0")
            .unwrap()
            .try_into()
            .unwrap();
        let dest_script = p2pkh_script_pubkey(&dest_pkh).to_vec();
        let unsigned = UnsignedTx {
            inputs: vec![TxInput {
                prevout: OutPoint {
                    txid: txid_from_display(FUNDING_TXID_DISPLAY).unwrap(),
                    vout: 1,
                },
                sequence: 0xffffffff,
            }],
            outputs: vec![
                TxOutput {
                    value_zat: 49_000_000,
                    script_pubkey: dest_script,
                },
                TxOutput {
                    value_zat: 900_000,
                    script_pubkey: script_pubkey.clone(),
                },
            ],
            lock_time: 0,
            expiry_height: 2_900_100,
        };
        (unsigned, script_pubkey, 50_000_000)
    }

    #[test]
    fn sighash_matches_independent_python_vector() {
        let (unsigned, script_code, value) = fixture();
        let sighash =
            zip243_sighash(&unsigned, 0, &script_code, value, TEST_BRANCH_ID).unwrap();
        assert_eq!(crate::keys::hex_encode(&sighash), EXPECTED_SIGHASH_HEX);
    }

    #[test]
    fn unsigned_serialization_length_matches_python() {
        let (unsigned, _, _) = fixture();
        let signed = SignedTx {
            unsigned,
            script_sigs: vec![vec![]],
        };
        assert_eq!(signed.serialize().unwrap().len(), EXPECTED_UNSIGNED_LEN);
    }

    #[test]
    fn sighash_is_deterministic_and_input_specific() {
        let (unsigned, script_code, value) = fixture();
        let a = zip243_sighash(&unsigned, 0, &script_code, value, TEST_BRANCH_ID).unwrap();
        let b = zip243_sighash(&unsigned, 0, &script_code, value, TEST_BRANCH_ID).unwrap();
        assert_eq!(a, b);
        // Different value -> different sighash (amount committed).
        let c =
            zip243_sighash(&unsigned, 0, &script_code, value + 1, TEST_BRANCH_ID).unwrap();
        assert_ne!(a, c);
        // Different branch id -> different sighash (replay protection).
        let d =
            zip243_sighash(&unsigned, 0, &script_code, value, TEST_BRANCH_ID ^ 1).unwrap();
        assert_ne!(a, d);
    }

    #[test]
    fn signature_verifies_against_sighash() {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let (unsigned, script_code, value) = fixture();
        let secret = SecretKey::from_slice(
            &unhex("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
        )
        .unwrap();
        let script_sig =
            sign_p2pkh_input(&unsigned, 0, &secret, &script_code, value, TEST_BRANCH_ID)
                .unwrap();
        // Parse scriptSig: push(sig) push(pubkey).
        assert_eq!(script_sig[0] as usize, script_sig.len() - 2 - 33);
        let sig_len = script_sig[0] as usize;
        let der = &script_sig[1..1 + sig_len];
        assert_eq!(der[sig_len - 1], SIGHASH_ALL as u8, "sighash type byte");
        assert_eq!(script_sig[1 + sig_len], 33u8);
        let pubkey_bytes = &script_sig[1 + sig_len + 1..];
        assert_eq!(pubkey_bytes.len(), 33);
        // Verify ECDSA over the sighash.
        let secp = Secp256k1::new();
        let sighash =
            zip243_sighash(&unsigned, 0, &script_code, value, TEST_BRANCH_ID).unwrap();
        let msg = Message::from_digest(sighash);
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&der[..sig_len - 1]).unwrap();
        let pubkey = bitcoin::secp256k1::PublicKey::from_slice(pubkey_bytes).unwrap();
        secp.verify_ecdsa(&msg, &sig, &pubkey).unwrap();
    }

    #[test]
    fn txid_display_reversal_roundtrip() {
        let internal = txid_from_display(FUNDING_TXID_DISPLAY).unwrap();
        assert_eq!(txid_to_display(&internal), FUNDING_TXID_DISPLAY);
        // Internal order is the byte-reverse of display order.
        let disp_bytes = unhex(FUNDING_TXID_DISPLAY).unwrap();
        assert_eq!(internal[0], disp_bytes[31]);
        assert_eq!(internal[31], disp_bytes[0]);
    }

    #[test]
    fn build_release_funds_and_change() {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secret = SecretKey::from_slice(
            &unhex("2222222222222222222222222222222222222222222222222222222222222222").unwrap(),
        )
        .unwrap();
        let secp = Secp256k1::new();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let compressed: [u8; 33] = pk.serialize();
        let script = p2pkh_script_pubkey(&hash160_of_pubkey(&compressed)).to_vec();
        let addr = p2pkh_testnet(&compressed);
        assert!(addr.starts_with("tm"));

        let dest_pkh = [0xccu8; 20];
        let dest_script = p2pkh_script_pubkey(&dest_pkh).to_vec();
        let op = OutPoint {
            txid: [0xabu8; 32],
            vout: 0,
        };
        let signed = build_release(
            &secret,
            &[(op, 100_000_000, script.clone())],
            dest_script,
            script.clone(),
            60_000_000,
            2_900_100,
            TEST_BRANCH_ID,
        )
        .unwrap();
        // Outputs: dest 60M, change 100M - 60M - 10k fee.
        assert_eq!(signed.unsigned.outputs.len(), 2);
        assert_eq!(signed.unsigned.outputs[0].value_zat, 60_000_000);
        assert_eq!(
            signed.unsigned.outputs[1].value_zat,
            100_000_000 - 60_000_000 - DEFAULT_FEE_ZAT
        );
        // Serialization parses: version + group id lead.
        let raw = signed.serialize().unwrap();
        assert_eq!(&raw[0..4], &VERSION.to_le_bytes());
        assert_eq!(&raw[4..8], &VERSION_GROUP_ID.to_le_bytes());
        // Txid is 32 bytes, display is 64 hex chars.
        assert_eq!(signed.txid_display().unwrap().len(), 64);
    }

    #[test]
    fn build_release_rejects_insufficient_funds() {
        use bitcoin::secp256k1::SecretKey;
        let secret = SecretKey::from_slice(
            &unhex("3333333333333333333333333333333333333333333333333333333333333333").unwrap(),
        )
        .unwrap();
        let op = OutPoint {
            txid: [0u8; 32],
            vout: 0,
        };
        let script = vec![0x76, 0xa9, 0x14];
        let err = build_release(
            &secret,
            &[(op, 1000, script.clone())],
            script.clone(),
            script,
            5000,
            1,
            TEST_BRANCH_ID,
        )
        .unwrap_err();
        assert!(matches!(err, TxError::Invalid(_)));
    }
}
