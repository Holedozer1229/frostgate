//! `frostgate-federation`: reusable FROST threshold-signing ceremony for federations.
//!
//! Built on the Zcash Foundation's `frost` crates implementing RFC 9591
//! (Flexible Round-Optimized Schnorr Threshold signatures).
//!
//! Two phases:
//! - DKG ceremony ([`run_dkg`]): 5 operators, threshold 3, no trusted dealer.
//! - Signing sessions ([`signing`]): coordinator builds the signing package,
//!   operators emit shares, coordinator aggregates a 64-byte BIP340
//!   threshold signature verifiable under the group key.
//!
//! # Audit-scope honesty
//! The ZF `frost-core` crates were assessed by NCC Group (v0.6.0 report,
//! Oct 2023). The Taproot ciphersuite crate used here,
//! `frost-secp256k1-tr`, was explicitly **not** in that audit's scope.
//! This crate is therefore described as "built on ZF's FROST implementation",
//! never as "audited".
//!
//! # Security notes
//! - DKG uses `frost-core`'s distributed key generation — no trusted dealer,
//!   no party ever holds the full secret key.
//! - Signing nonces MUST be fresh per session and zeroized after use.
//!   Never reuse a `(D_i, E_i)` commitment pair across sessions.
//! - The coordinator is trusted for liveness and message integrity: signers
//!   must verify `SigningPackage` contents, and operator<->coordinator
//!   channels must be authenticated.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use frost_core::{
    self as frost,
    keys::{
        dkg::{part1, part2, part3},
        KeyPackage,
    },
};
use frost_secp256k1_tr::Secp256K1Sha256TR;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod signing;

pub use frost_core::keys::PublicKeyPackage;
/// Re-exported FROST types so downstream crates (coordinator, relay) name
/// the same types without adding their own frost-core dependency. These
/// `pub use` items also stay in scope for this module's own code below.
pub use frost_core::{round1, round2, Identifier, SigningPackage};
pub use signing::{cheater_culprits, Coordinator, OperatorSigner};

/// The FROST ciphersuite: secp256k1 Schnorr with Taproot (BIP340/BIP341)
/// compatibility. A threshold signature from the quorum is a single 64-byte
/// Schnorr signature verifiable under the group key.
pub type FgSuite = Secp256K1Sha256TR;

/// Errors from the ceremony.
#[derive(Debug, Error)]
pub enum CeremonyError {
    #[error("frost error: {0}")]
    Frost(#[from] frost::Error<FgSuite>),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid ceremony: {0}")]
    Invalid(String),
}

/// Ceremony parameters: `threshold`-of-`num_operators`.
#[derive(Debug, Clone, Copy)]
pub struct CeremonyConfig {
    pub num_operators: u16,
    pub threshold: u16,
}

impl CeremonyConfig {
    pub fn new(num_operators: u16, threshold: u16) -> Result<Self, CeremonyError> {
        if num_operators == 0 || threshold == 0 || threshold > num_operators {
            return Err(CeremonyError::Invalid(format!(
                "need 0 < threshold <= num_operators, got threshold={threshold} operators={num_operators}"
            )));
        }
        Ok(Self {
            num_operators,
            threshold,
        })
    }
}

/// One operator's output from the DKG ceremony.
pub struct OperatorKeys {
    pub identifier: Identifier<FgSuite>,
    pub key_package: KeyPackage<FgSuite>,
    pub public_key_package: PublicKeyPackage<FgSuite>,
}

/// Run the full FROST DKG ceremony in-process.
///
/// Message transport is simulated as an in-memory broadcast here; the
/// networked operator relay replaces it later (the ceremony math is
/// unchanged). Returns one [`OperatorKeys`] per operator, ordered by
/// identifier.
///
/// After round 3, every operator's public key package must derive the
/// identical group verifying key — the ceremony fails otherwise.
pub fn run_dkg<R: RngCore + CryptoRng>(
    config: CeremonyConfig,
    mut rng: R,
) -> Result<Vec<OperatorKeys>, CeremonyError> {
    let n = config.num_operators;
    let t = config.threshold;

    // ---- Round 1: each participant commits to its polynomial ----
    // Note: part1 takes the RNG by value; `&mut R` itself implements
    // RngCore + CryptoRng, so we reborrow per participant.
    let mut r1_secrets: Vec<(
        Identifier<FgSuite>,
        frost::keys::dkg::round1::SecretPackage<FgSuite>,
    )> = Vec::new();
    let mut r1_packages: BTreeMap<Identifier<FgSuite>, frost::keys::dkg::round1::Package<FgSuite>> =
        BTreeMap::new();
    for i in 1..=n {
        let id = Identifier::try_from(i)?;
        let (secret, package) = part1::<FgSuite, &mut R>(id, n, t, &mut rng)?;
        r1_secrets.push((id, secret));
        r1_packages.insert(id, package);
    }

    // ---- Round 2: each participant processes everyone else's round-1 package ----
    let mut r2_secrets: Vec<(
        Identifier<FgSuite>,
        frost::keys::dkg::round2::SecretPackage<FgSuite>,
    )> = Vec::new();
    // r2_out[sender][recipient] = package
    let mut r2_out: BTreeMap<
        Identifier<FgSuite>,
        BTreeMap<Identifier<FgSuite>, frost::keys::dkg::round2::Package<FgSuite>>,
    > = BTreeMap::new();
    for (id, secret) in r1_secrets {
        let mut received = r1_packages.clone();
        received.remove(&id);
        let (secret2, packages) = part2(secret, &received)?;
        r2_secrets.push((id, secret2));
        r2_out.insert(id, packages);
    }

    // ---- Round 3: derive key packages ----
    let mut out = Vec::new();
    for (id, secret2) in r2_secrets {
        let mut r1_received = r1_packages.clone();
        r1_received.remove(&id);
        let mut r2_received: BTreeMap<
            Identifier<FgSuite>,
            frost::keys::dkg::round2::Package<FgSuite>,
        > = BTreeMap::new();
        for (sender, map) in &r2_out {
            if sender == &id {
                continue;
            }
            if let Some(pkg) = map.get(&id) {
                r2_received.insert(*sender, pkg.clone());
            }
        }
        let (key_package, public_key_package) = part3(&secret2, &r1_received, &r2_received)?;
        out.push(OperatorKeys {
            identifier: id,
            key_package,
            public_key_package,
        });
    }

    // ---- Consistency: identical group key across all operators ----
    let group_key = out[0].public_key_package.verifying_key();
    for op in &out[1..] {
        if op.public_key_package.verifying_key() != group_key {
            return Err(CeremonyError::Invalid(
                "DKG produced divergent group keys".to_string(),
            ));
        }
    }
    Ok(out)
}

/// Hex encoding of the group verifying key (compressed point bytes).
pub fn group_key_hex(
    public_key_package: &PublicKeyPackage<FgSuite>,
) -> Result<String, CeremonyError> {
    let bytes = public_key_package.verifying_key().serialize()?;
    Ok(hex_bytes(&bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

const OPERATOR_FILE_FORMAT: &str = "frostgate-operator-keys/1";
const GROUP_FILE_FORMAT: &str = "frostgate-group-keys/1";

#[derive(Serialize, Deserialize)]
struct OperatorFile {
    format: String,
    identifier_u16: u16,
    /// Secret share (serde-supported on KeyPackage).
    key_package: KeyPackage<FgSuite>,
    /// Group public package, hex-encoded via its byte serialization
    /// (PublicKeyPackage is Serialize-only under serde, so bytes it is).
    public_key_package_hex: String,
}

#[derive(Serialize, Deserialize)]
struct GroupFile {
    format: String,
    num_operators: u16,
    threshold: u16,
    public_key_package_hex: String,
    group_verifying_key_hex: String,
}

fn pubkey_pkg_hex(pkg: &PublicKeyPackage<FgSuite>) -> Result<String, CeremonyError> {
    Ok(hex_bytes(&pkg.serialize()?))
}

fn pubkey_pkg_from_hex(hex: &str) -> Result<PublicKeyPackage<FgSuite>, CeremonyError> {
    let bytes = unhex(hex)?;
    Ok(PublicKeyPackage::deserialize(&bytes)?)
}

fn unhex(s: &str) -> Result<Vec<u8>, CeremonyError> {
    if !s.len().is_multiple_of(2) {
        return Err(CeremonyError::Invalid("odd-length hex".to_string()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i]).ok_or_else(|| CeremonyError::Invalid("bad hex".to_string()))?;
        let lo =
            hex_val(bytes[i + 1]).ok_or_else(|| CeremonyError::Invalid("bad hex".to_string()))?;
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

/// Persist one ceremony to `dir`:
/// `operator-{i}.json` (secret — protect like a key file) and `group.json` (public).
pub fn save_ceremony(
    dir: &Path,
    config: CeremonyConfig,
    operators: &[OperatorKeys],
) -> Result<(), CeremonyError> {
    fs::create_dir_all(dir)?;
    let mut identifier_of_index: BTreeMap<u16, u16> = BTreeMap::new();
    for (idx, op) in operators.iter().enumerate() {
        // Identifier -> u16 is not directly exposed; recover the small index by
        // matching against the known 1..=n range.
        let mut found = None;
        for i in 1..=config.num_operators {
            if Identifier::try_from(i)
                .map(|x| x == op.identifier)
                .unwrap_or(false)
            {
                found = Some(i);
                break;
            }
        }
        let i = found.ok_or_else(|| {
            CeremonyError::Invalid("operator identifier out of ceremony range".to_string())
        })?;
        identifier_of_index.insert(idx as u16, i);
        let file = OperatorFile {
            format: OPERATOR_FILE_FORMAT.to_string(),
            identifier_u16: i,
            key_package: op.key_package.clone(),
            public_key_package_hex: pubkey_pkg_hex(&op.public_key_package)?,
        };
        let path = dir.join(format!("operator-{i}.json"));
        fs::write(&path, serde_json::to_string_pretty(&file)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
    }
    let group_hex = group_key_hex(&operators[0].public_key_package)?;
    let group = GroupFile {
        format: GROUP_FILE_FORMAT.to_string(),
        num_operators: config.num_operators,
        threshold: config.threshold,
        public_key_package_hex: pubkey_pkg_hex(&operators[0].public_key_package)?,
        group_verifying_key_hex: group_hex,
    };
    fs::write(
        dir.join("group.json"),
        serde_json::to_string_pretty(&group)?,
    )?;
    Ok(())
}

/// Load one operator's persisted key material.
pub fn load_operator(dir: &Path, index: u16) -> Result<OperatorKeys, CeremonyError> {
    let raw = fs::read(dir.join(format!("operator-{index}.json")))?;
    let file: OperatorFile = serde_json::from_slice(&raw)?;
    if file.format != OPERATOR_FILE_FORMAT {
        return Err(CeremonyError::Invalid(format!(
            "unexpected operator file format: {}",
            file.format
        )));
    }
    Ok(OperatorKeys {
        identifier: Identifier::try_from(file.identifier_u16)?,
        key_package: file.key_package,
        public_key_package: pubkey_pkg_from_hex(&file.public_key_package_hex)?,
    })
}

/// Load the public group package.
pub fn load_group(dir: &Path) -> Result<PublicKeyPackage<FgSuite>, CeremonyError> {
    let raw = fs::read(dir.join("group.json"))?;
    let file: GroupFile = serde_json::from_slice(&raw)?;
    if file.format != GROUP_FILE_FORMAT {
        return Err(CeremonyError::Invalid(format!(
            "unexpected group file format: {}",
            file.format
        )));
    }
    pubkey_pkg_from_hex(&file.public_key_package_hex)
}

/// Map a FROST identifier back to its 1-based operator index.
///
/// The DKG in this crate assigns identifiers `1..=num_operators`; this is the
/// inverse used for cheater attribution in coordinator reports.
pub fn identifier_index(id: &Identifier<FgSuite>, num_operators: u16) -> Option<u16> {
    (1..=num_operators).find(|&i| Identifier::try_from(i).map(|x| &x == id).unwrap_or(false))
}

/// Convenience: path helper for ceremony directories.
pub fn operator_path(dir: &Path, index: u16) -> PathBuf {
    dir.join(format!("operator-{index}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn dkg_group_key_agreement_5_of_3() {
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        assert_eq!(ops.len(), 5);
        let group_key = ops[0].public_key_package.verifying_key();
        for op in &ops[1..] {
            assert_eq!(
                op.public_key_package.verifying_key(),
                group_key,
                "all operators must derive the same group key"
            );
        }
        // Each operator's verifying share must be present in the group package.
        for op in &ops {
            let share = op.key_package.verifying_share();
            assert_eq!(
                op.public_key_package.verifying_shares().get(&op.identifier),
                Some(share),
                "group package must contain this operator's verifying share"
            );
        }
    }

    #[test]
    fn dkg_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        save_ceremony(dir.path(), config, &ops).unwrap();

        let group_before = group_key_hex(&ops[0].public_key_package).unwrap();
        let group_pkg = load_group(dir.path()).unwrap();
        assert_eq!(group_key_hex(&group_pkg).unwrap(), group_before);

        for i in 1..=5u16 {
            let reloaded = load_operator(dir.path(), i).unwrap();
            assert_eq!(
                group_key_hex(&reloaded.public_key_package).unwrap(),
                group_before
            );
            assert_eq!(
                reloaded.key_package.verifying_share(),
                ops[(i - 1) as usize].key_package.verifying_share()
            );
        }
    }

    #[test]
    fn dkg_rejects_bad_config() {
        assert!(CeremonyConfig::new(0, 0).is_err());
        assert!(CeremonyConfig::new(5, 0).is_err());
        assert!(CeremonyConfig::new(5, 6).is_err());
        assert!(CeremonyConfig::new(3, 3).is_ok());
    }

    #[test]
    fn dkg_small_ceremony_works() {
        let config = CeremonyConfig::new(3, 2).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        assert_eq!(ops.len(), 3);
        let gk = ops[0].public_key_package.verifying_key();
        assert!(ops[1..]
            .iter()
            .all(|op| op.public_key_package.verifying_key() == gk));
    }
}
