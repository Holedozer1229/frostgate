//! Settlement journal: replay protection for the coordinator.
//!
//! Records every settled peg-in outpoint and every attestation nonce. A
//! peg-in outpoint settles at most once; a nonce is never reused. The demo
//! runs the journal in memory; `watch` mode persists it to disk.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("replay rejected: {0}")]
    Replay(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub nonce_hex: String,
    pub release_txid: String,
    pub release_zat: u64,
}

/// Canonical outpoint key: `{txid_display}:{vout}`.
pub fn outpoint_key(txid_display: &str, vout: u32) -> String {
    format!("{txid_display}:{vout}")
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Journal {
    settled: HashMap<String, JournalEntry>,
    nonces: HashSet<String>,
}

impl Journal {
    pub fn is_settled(&self, txid_display: &str, vout: u32) -> bool {
        self.settled.contains_key(&outpoint_key(txid_display, vout))
    }

    pub fn nonce_used(&self, nonce_hex: &str) -> bool {
        self.nonces.contains(nonce_hex)
    }

    /// Record a settlement. Fails if the outpoint was already settled or the
    /// nonce was already used — replay is refused, never silently merged.
    pub fn record(
        &mut self,
        txid_display: &str,
        vout: u32,
        entry: JournalEntry,
    ) -> Result<(), JournalError> {
        let key = outpoint_key(txid_display, vout);
        if self.settled.contains_key(&key) {
            return Err(JournalError::Replay(format!(
                "peg-in {key} already settled"
            )));
        }
        if !self.nonces.insert(entry.nonce_hex.clone()) {
            return Err(JournalError::Replay(format!(
                "attestation nonce {} already used",
                entry.nonce_hex
            )));
        }
        self.settled.insert(key, entry);
        Ok(())
    }

    pub fn settled_count(&self) -> usize {
        self.settled.len()
    }

    pub fn save(&self, path: &Path) -> Result<(), JournalError> {
        let raw = serde_json::to_string_pretty(self)?;
        std::fs::write(path, raw)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, JournalError> {
        let raw = std::fs::read(path)?;
        Ok(serde_json::from_slice(&raw)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(nonce: &str) -> JournalEntry {
        JournalEntry {
            nonce_hex: nonce.to_string(),
            release_txid: "tx".to_string(),
            release_zat: 1,
        }
    }

    #[test]
    fn double_settle_rejected() {
        let mut j = Journal::default();
        j.record("aa", 0, entry("n1")).unwrap();
        assert!(j.is_settled("aa", 0));
        assert!(!j.is_settled("aa", 1));
        assert!(j.record("aa", 0, entry("n2")).is_err());
    }

    #[test]
    fn nonce_reuse_rejected() {
        let mut j = Journal::default();
        j.record("aa", 0, entry("n1")).unwrap();
        assert!(j.nonce_used("n1"));
        assert!(j.record("bb", 0, entry("n1")).is_err());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        let mut j = Journal::default();
        j.record("aa", 0, entry("n1")).unwrap();
        j.save(&path).unwrap();
        let j2 = Journal::load(&path).unwrap();
        assert!(j2.is_settled("aa", 0));
        assert!(j2.nonce_used("n1"));
    }
}
