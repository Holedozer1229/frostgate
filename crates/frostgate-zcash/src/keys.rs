//! Coordinator release key (Zcash leg).
//!
//! # Trust model (read this)
//! The ZEC-side vault is a **hot key held by the coordinator**, not a
//! threshold key. What the 3-of-5 FROST quorum controls is the
//! *authorization*: a release transaction is only built after the operators
//! threshold-sign a [`crate::attest::ReleaseAttestation`] naming the exact
//! destination, amount, and peg-in outpoint. Execution is 1-of-1;
//! authorization is 3-of-5.
//!
//! Why not threshold-sign the ZEC spend directly? Zcash transparent inputs
//! require ECDSA signatures; FROST (RFC 9591) is a Schnorr scheme and the ZF
//! crates cannot produce ECDSA. A threshold-ECDSA ceremony would be a new,
//! unaudited protocol — out of scope and less safe than the attestation
//! design. This is documented, not hidden.

use std::fs;
use std::path::Path;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid key: {0}")]
    Invalid(String),
    #[error("secp256k1 error: {0}")]
    Secp(#[from] bitcoin::secp256k1::Error),
}

const KEY_FILE_FORMAT: &str = "frostgate-zcash-release-key/1";

#[derive(Serialize, Deserialize)]
struct KeyFile {
    format: String,
    network: String,
    /// 32-byte secret, hex-encoded.
    secret_hex: String,
}

/// The coordinator's ZEC release key (secp256k1, testnet only in this build).
pub struct ReleaseKey {
    secret: SecretKey,
}

impl ReleaseKey {
    /// Generate a fresh key from the OS CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, KeyError> {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let secret = SecretKey::from_slice(&bytes)
            .map_err(|_| KeyError::Invalid("rng produced invalid secret".to_string()))?;
        // Best-effort wipe of the stack buffer.
        for b in bytes.iter_mut() {
            *b = 0;
        }
        Ok(Self { secret })
    }

    /// Load from 32 raw bytes (e.g. a previously exported secret).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let secret = SecretKey::from_slice(bytes)
            .map_err(|e| KeyError::Invalid(format!("bad secret: {e}")))?;
        Ok(Self { secret })
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.secret_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.secret)
    }

    /// Compressed 33-byte public key.
    pub fn public_key_compressed(&self) -> [u8; 33] {
        self.public_key().serialize()
    }

    /// Persist to `path` with mode 0600. Secret key material — never commit.
    pub fn save(&self, path: &Path) -> Result<(), KeyError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = KeyFile {
            format: KEY_FILE_FORMAT.to_string(),
            network: "zcash-testnet".to_string(),
            secret_hex: hex_encode(&self.secret_bytes()),
        };
        fs::write(path, serde_json::to_string_pretty(&file)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load a previously saved key. Refuses files for another network or
    /// an unrecognized format.
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let raw = fs::read(path)?;
        let file: KeyFile = serde_json::from_slice(&raw)?;
        if file.format != KEY_FILE_FORMAT {
            return Err(KeyError::Invalid(format!(
                "unexpected key file format: {}",
                file.format
            )));
        }
        if file.network != "zcash-testnet" {
            return Err(KeyError::Invalid(format!(
                "key file is for network '{}', this build is zcash-testnet only",
                file.network
            )));
        }
        Self::from_bytes(&unhex(&file.secret_hex)?)
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Result<Vec<u8>, KeyError> {
    if !s.len().is_multiple_of(2) {
        return Err(KeyError::Invalid("odd-length hex".to_string()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i]).ok_or_else(|| KeyError::Invalid("bad hex".to_string()))?;
        let lo = hex_val(bytes[i + 1]).ok_or_else(|| KeyError::Invalid("bad hex".to_string()))?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn keygen_produces_valid_keypair() {
        let key = ReleaseKey::generate(&mut OsRng).unwrap();
        let pk = key.public_key_compressed();
        assert!(pk[0] == 0x02 || pk[0] == 0x03);
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join("frostgate-zcash-test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("release-key.json");
        let key = ReleaseKey::generate(&mut OsRng).unwrap();
        key.save(&path).unwrap();
        let reloaded = ReleaseKey::load(&path).unwrap();
        assert_eq!(reloaded.secret_bytes(), key.secret_bytes());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_wrong_network() {
        let dir = std::env::temp_dir().join("frostgate-zcash-test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("bad-net-key.json");
        let file = KeyFile {
            format: KEY_FILE_FORMAT.to_string(),
            network: "zcash-mainnet".to_string(),
            secret_hex: "00".repeat(32),
        };
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        assert!(ReleaseKey::load(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn from_bytes_rejects_invalid() {
        assert!(ReleaseKey::from_bytes(&[0u8; 32]).is_err());
        assert!(ReleaseKey::from_bytes(&[1u8; 31]).is_err());
    }
}
