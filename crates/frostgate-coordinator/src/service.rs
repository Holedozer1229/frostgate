//! The coordinator service: peg-in scan -> FROST signing session -> ZEC release.
//!
//! [`CoordinatorService::settle`] is the whole D5 pipeline for one peg-in:
//! build the [`ReleaseAttestation`](frostgate_zcash::attest::ReleaseAttestation),
//! threshold-sign it with any 3 of the 5 operators through the
//! [`crate::relay::OperatorRelay`], verify the quorum signature, then build
//! and broadcast the Zcash release transaction.
//!
//! Cheater handling: if aggregation fails with cheater attribution, the
//! culprits are excluded and the session is retried once with the remaining
//! honest operators (4 honest of 5 still clears the threshold of 3). The
//! excluded cheaters are named in the [`SettlementReport`].

use frostgate_bitcoin::watcher::{peg_in_utxos, WatcherError, BLOCKSTREAM_TESTNET};
use frostgate_federation::{
    cheater_culprits, identifier_index, CeremonyError, Coordinator, FgSuite, Identifier,
    SigningPackage,
};
use frostgate_zcash::address::AddressError;
use frostgate_zcash::attest::{AttestError, ReleaseAttestation, SignedAttestation};
use frostgate_zcash::client::{ChainClient, ClientError};
use frostgate_zcash::keys::{hex_encode, unhex, KeyError, ReleaseKey};
use frostgate_zcash::tx::{txid_from_display, OutPoint, TxError};
use rand::rngs::OsRng;
use rand_core::RngCore;
use thiserror::Error;

use crate::journal::{Journal, JournalEntry, JournalError};
use crate::relay::{OperatorRelay, RelayError};

#[derive(Debug, Error)]
pub enum CoordError {
    #[error("ceremony error: {0}")]
    Ceremony(#[from] CeremonyError),
    #[error("relay error: {0}")]
    Relay(#[from] RelayError),
    #[error("journal error: {0}")]
    Journal(#[from] JournalError),
    #[error("attestation error: {0}")]
    Attest(#[from] AttestError),
    #[error("chain client error: {0}")]
    Client(#[from] ClientError),
    #[error("transaction error: {0}")]
    Tx(#[from] TxError),
    #[error("watcher error: {0}")]
    Watcher(#[from] WatcherError),
    #[error("key error: {0}")]
    Key(#[from] KeyError),
    #[error("address error: {0}")]
    Address(#[from] AddressError),
    #[error("coordinator error: {0}")]
    Invalid(String),
}

/// Static configuration for the service.
pub struct ServiceConfig {
    /// Esplora base URL (default: [`BLOCKSTREAM_TESTNET`]).
    pub esplora_base: String,
    /// ZEC destination (testnet P2PKH `tm…`) for releases.
    pub dest_zec_address: String,
    /// Funding outpoint of the coordinator-held ZEC vault (display txid).
    pub vault_txid_display: String,
    pub vault_vout: u32,
    /// Expiry = chain height + this many blocks.
    pub expiry_delta: u32,
    /// Consensus branch ID for the ZIP-243 sighash (e.g. 0x37A5165B for
    /// testnet on 2026-09-30). Must match the network epoch.
    pub consensus_branch_id: u32,
}

impl ServiceConfig {
    pub fn demo(dest_zec_address: String, vault_txid_display: String, vault_vout: u32) -> Self {
        Self {
            esplora_base: BLOCKSTREAM_TESTNET.to_string(),
            dest_zec_address,
            vault_txid_display,
            vault_vout,
            expiry_delta: 20,
            consensus_branch_id: 0x37A5165B, // testnet, 2026-09-30
        }
    }
}

/// A confirmed peg-in UTXO paying the federation address.
#[derive(Debug, Clone)]
pub struct PegIn {
    pub txid_display: String,
    pub vout: u32,
    pub sats: u64,
}

/// What `settle` did, with everything a verifier needs to check it.
#[derive(Debug, Clone)]
pub struct SettlementReport {
    pub pegin_txid_display: String,
    pub pegin_vout: u32,
    pub release_zat: u64,
    pub toll_zat: u64,
    /// 1-based operator indices whose shares formed the quorum.
    pub signers: Vec<u16>,
    /// 1-based operator indices excluded as cheaters (empty in the honest path).
    pub excluded_cheaters: Vec<u16>,
    pub attestation: SignedAttestation,
    pub release_txid: String,
    pub release_tx_hex: String,
}

/// Demo peg: 1 sat of peg-in releases 1 zat, minus the 30 bps toll.
/// This is a testnet demo rate, not an oracle — documented, not hidden.
fn demo_release_zat(pegin_sats: u64) -> u64 {
    pegin_sats
}

/// The coordinator service. `C` is the Zcash chain client (`MockChain` in
/// tests and demos, `ZcashRpc` live).
pub struct CoordinatorService<C: ChainClient> {
    coord: Coordinator,
    group_xonly: [u8; 32],
    num_operators: u16,
    threshold: usize,
    relay: OperatorRelay,
    chain: C,
    release_key: ReleaseKey,
    vault_script: Vec<u8>,
    journal: Journal,
    config: ServiceConfig,
}

impl<C: ChainClient> CoordinatorService<C> {
    /// Build the service. `group_pkg` is the ceremony's public package;
    /// `num_operators`/`threshold` describe the federation (5/3 in the demo).
    pub fn new(
        group_pkg: frostgate_federation::PublicKeyPackage<FgSuite>,
        num_operators: u16,
        threshold: usize,
        relay: OperatorRelay,
        chain: C,
        release_key: ReleaseKey,
        config: ServiceConfig,
    ) -> Result<Self, CoordError> {
        let coord = Coordinator::new(group_pkg.clone());
        let vk_bytes = group_pkg
            .verifying_key()
            .serialize()
            .map_err(CeremonyError::Frost)?;
        // The TR ciphersuite serializes the verifying key compressed (33
        // bytes, 0x02/0x03 prefix); the x-only key is bytes [1..33]. Accept
        // a bare 32-byte x-only encoding too.
        let mut group_xonly = [0u8; 32];
        match vk_bytes.as_slice() {
            [0x02 | 0x03, x @ ..] if x.len() == 32 => group_xonly.copy_from_slice(x),
            x if x.len() == 32 => group_xonly.copy_from_slice(x),
            _ => {
                return Err(CoordError::Invalid(format!(
                    "unexpected group verifying key encoding ({} bytes)",
                    vk_bytes.len()
                )))
            }
        }

        // The vault is the P2PKH of the coordinator release key.
        let pkh = frostgate_zcash::address::hash160_of_pubkey(&release_key.public_key_compressed());
        let vault_script = frostgate_zcash::address::p2pkh_script_pubkey(&pkh).to_vec();

        Ok(Self {
            coord,
            group_xonly,
            num_operators,
            threshold,
            relay,
            chain,
            release_key,
            vault_script,
            journal: Journal::default(),
            config,
        })
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    pub fn set_journal(&mut self, journal: Journal) {
        self.journal = journal;
    }

    /// Scan the federation address for new confirmed peg-ins (journaled
    /// outpoints excluded).
    pub fn scan_pegins(&self, federation_address: &str) -> Result<Vec<PegIn>, CoordError> {
        let utxos = peg_in_utxos(&self.config.esplora_base, federation_address)?;
        Ok(utxos
            .into_iter()
            .filter(|u| !self.journal.is_settled(&u.txid, u.vout))
            .map(|u| PegIn {
                txid_display: u.txid,
                vout: u.vout,
                sats: u.value,
            })
            .collect())
    }

    /// One FROST signing session over `message` with the given exclusions.
    /// Returns the 64-byte signature and the signer indices used.
    fn run_session(
        &mut self,
        message: &[u8],
        exclude: &[u16],
    ) -> Result<(Vec<u8>, Vec<u16>), CoordError> {
        let mut candidates: Vec<u16> = self
            .relay
            .online_ids()
            .into_iter()
            .filter(|id| !exclude.contains(id))
            .collect();
        if candidates.len() < self.threshold {
            return Err(CoordError::Invalid(format!(
                "insufficient signers: {} available ({} excluded), need {}",
                candidates.len(),
                exclude.len(),
                self.threshold
            )));
        }
        candidates.truncate(self.threshold);

        let mut rng = OsRng;
        let commitments = self.relay.commit(&candidates, &mut rng)?;
        let package: SigningPackage<FgSuite> = self.coord.build_package(commitments, message)?;
        let shares = self.relay.sign(&package)?;
        let sig = self.coord.aggregate(&package, &shares)?;
        self.coord.verify(message, &sig)?;
        let bytes = Coordinator::signature_bytes(&sig)?;
        Ok((bytes, candidates))
    }

    /// Settle one peg-in: attest -> threshold-sign -> verify -> build ZEC
    /// release -> broadcast. On cheater attribution the culprits are excluded
    /// and the session retried once with the remaining honest operators.
    pub fn settle(&mut self, pegin: &PegIn) -> Result<SettlementReport, CoordError> {
        if self.journal.is_settled(&pegin.txid_display, pegin.vout) {
            return Err(CoordError::Invalid(format!(
                "peg-in {}:{} already settled (replay refused)",
                pegin.txid_display, pegin.vout
            )));
        }

        // ---- Attestation ----
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let nonce_hex = hex_encode(&nonce);
        let height = self.chain.height()?;
        let expiry_height: u32 = u32::try_from(height)
            .map_err(|_| CoordError::Invalid("chain height overflows u32".to_string()))?
            .saturating_add(self.config.expiry_delta);
        let release_zat = demo_release_zat(pegin.sats);
        let attestation = ReleaseAttestation {
            pegin_txid_display: pegin.txid_display.clone(),
            pegin_vout: pegin.vout,
            pegin_sats: pegin.sats,
            dest_address: self.config.dest_zec_address.clone(),
            release_zat,
            toll_zat: release_zat * 30 / 10_000,
            nonce_hex: nonce_hex.clone(),
            expiry_height,
        };
        attestation.validate()?;
        let message = attestation.message()?;

        // ---- Threshold signing (with cheater exclusion retry) ----
        let mut excluded_cheaters: Vec<u16> = Vec::new();
        let (sig_bytes, signer_ids) = match self.run_session(&message, &[]) {
            Ok(ok) => ok,
            Err(first_err) => {
                let culprits = cheater_culprits_id16(&first_err, self.num_operators);
                match culprits {
                    Some(ids) if !ids.is_empty() => {
                        excluded_cheaters = ids;
                        self.run_session(&message, &excluded_cheaters).map_err(|retry_err| {
                            CoordError::Invalid(format!(
                                "session failed after excluding cheaters {excluded_cheaters:?}: {retry_err}"
                            ))
                        })?
                    }
                    _ => return Err(first_err),
                }
            }
        };

        let signed = SignedAttestation {
            attestation: attestation.clone(),
            signature_hex: hex_encode(&sig_bytes),
            signers: signer_ids.clone(),
        };
        // Independent re-verification of the quorum signature (D4 path).
        signed.verify(&self.group_xonly)?;

        // ---- ZEC release ----
        let vault_utxo = self
            .chain
            .get_utxo(&self.config.vault_txid_display, self.config.vault_vout)?
            .ok_or_else(|| {
                CoordError::Invalid(format!(
                    "vault outpoint {}:{} not found — fund the coordinator vault first",
                    self.config.vault_txid_display, self.config.vault_vout
                ))
            })?;
        let chain_script = unhex(&vault_utxo.script_pubkey_hex)
            .map_err(|e| CoordError::Invalid(format!("bad vault script hex: {e}")))?;
        if chain_script != self.vault_script {
            return Err(CoordError::Invalid(
                "vault scriptPubKey on chain does not match the coordinator release key — refusing to spend".to_string(),
            ));
        }
        let dest_pkh =
            frostgate_zcash::address::parse_p2pkh_testnet(&self.config.dest_zec_address)?;
        let dest_script = frostgate_zcash::address::p2pkh_script_pubkey(&dest_pkh).to_vec();
        let inputs = vec![(
            OutPoint {
                txid: txid_from_display(&self.config.vault_txid_display)?,
                vout: self.config.vault_vout,
            },
            vault_utxo.value_zat,
            self.vault_script.clone(),
        )];
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&self.release_key.secret_bytes())
            .map_err(|e| CoordError::Invalid(format!("bad release key: {e}")))?;
        let signed_tx = frostgate_zcash::tx::build_release(
            &sk,
            &inputs,
            dest_script,
            self.vault_script.clone(),
            release_zat,
            expiry_height,
            self.config.consensus_branch_id,
        )?;
        let tx_hex = signed_tx.hex()?;
        let release_txid = self.chain.broadcast(&tx_hex)?;

        self.journal.record(
            &pegin.txid_display,
            pegin.vout,
            JournalEntry {
                nonce_hex,
                release_txid: release_txid.clone(),
                release_zat,
            },
        )?;

        Ok(SettlementReport {
            pegin_txid_display: pegin.txid_display.clone(),
            pegin_vout: pegin.vout,
            release_zat,
            toll_zat: release_zat * 30 / 10_000,
            signers: signer_ids,
            excluded_cheaters,
            attestation: signed,
            release_txid,
            release_tx_hex: tx_hex,
        })
    }
}

/// Map a session error's cheater culprits (FROST identifiers) back to
/// 1-based operator indices. `None` if the error carries no attribution.
fn cheater_culprits_id16(err: &CoordError, num_operators: u16) -> Option<Vec<u16>> {
    let cer = match err {
        CoordError::Ceremony(c) => c,
        CoordError::Relay(RelayError::Ceremony(c)) => c,
        _ => return None,
    };
    let ids: Vec<Identifier<FgSuite>> = cheater_culprits(cer)?.into_iter().collect();
    let mut out: Vec<u16> = ids
        .iter()
        .filter_map(|id| identifier_index(id, num_operators))
        .collect();
    out.sort_unstable();
    out.dedup();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frostgate_federation::{load_group, run_dkg, save_ceremony, CeremonyConfig};
    use frostgate_zcash::client::MockChain;
    use frostgate_zcash::keys::ReleaseKey;

    /// Fresh ceremony + relay + funded mock chain, ready to settle.
    fn harness(fault: crate::RelayFault) -> (CoordinatorService<MockChain>, PegIn) {
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        let group_pkg = ops[0].public_key_package.clone();
        let relay = OperatorRelay::from_operators(ops, fault).unwrap();

        let mut chain = MockChain {
            height: 2_900_000,
            ..Default::default()
        };
        let release_key = ReleaseKey::generate(&mut OsRng).unwrap();
        let pkh = frostgate_zcash::address::hash160_of_pubkey(&release_key.public_key_compressed());
        let vault_script = frostgate_zcash::address::p2pkh_script_pubkey(&pkh).to_vec();
        let vault_script_hex = hex_encode(&vault_script);
        let vault_txid = "ab".repeat(32);
        // Vault funded with 1 ZEC; peg-in below is 0.5 BTC -> 0.5 ZEC release.
        chain.fund(&vault_txid, 0, 100_000_000, &vault_script_hex);

        let dest_key = ReleaseKey::generate(&mut OsRng).unwrap();
        let dest_addr = frostgate_zcash::address::p2pkh_testnet(&dest_key.public_key_compressed());
        let cfg = ServiceConfig::demo(dest_addr, vault_txid.clone(), 0);
        let svc = CoordinatorService::new(group_pkg, 5, 3, relay, chain, release_key, cfg).unwrap();

        let pegin = PegIn {
            txid_display: "cd".repeat(32),
            vout: 0,
            sats: 50_000_000,
        };
        (svc, pegin)
    }

    #[test]
    fn settle_end_to_end_mockchain() {
        let (mut svc, pegin) = harness(crate::RelayFault::none());
        let rep = svc.settle(&pegin).unwrap();
        assert_eq!(rep.release_zat, 50_000_000);
        assert_eq!(rep.toll_zat, 50_000_000 * 30 / 10_000);
        assert_eq!(rep.signers.len(), 3);
        assert!(rep.excluded_cheaters.is_empty());
        assert_eq!(rep.release_txid.len(), 64);
        // The quorum signature re-verifies against the group key (D4 path).
        rep.attestation.verify(&svc.group_xonly).unwrap();
        // Journal blocks replay.
        assert!(svc.journal().is_settled(&pegin.txid_display, pegin.vout));
        assert!(svc.settle(&pegin).is_err());
    }

    #[test]
    fn two_operators_offline_still_settles() {
        // D6(a): operators 1 and 2 dark — the remaining 3 of 5 complete it.
        let (mut svc, pegin) = harness(crate::RelayFault::none().offline(&[1, 2]));
        let rep = svc.settle(&pegin).unwrap();
        assert_eq!(rep.signers, vec![3, 4, 5]);
        assert!(rep.excluded_cheaters.is_empty());
        rep.attestation.verify(&svc.group_xonly).unwrap();
    }

    #[test]
    fn malicious_share_detected_attributed_and_excluded() {
        // D6(b): operator 2 submits a bad share — detected, attributed,
        // excluded, session retried with the honest 4 (3 used).
        let (mut svc, pegin) = harness(crate::RelayFault::none().corrupt_share(2));
        let rep = svc.settle(&pegin).unwrap();
        assert_eq!(rep.excluded_cheaters, vec![2]);
        assert_eq!(rep.signers.len(), 3);
        assert!(!rep.signers.contains(&2));
        rep.attestation.verify(&svc.group_xonly).unwrap();
    }

    #[test]
    fn all_but_two_offline_fails_cleanly() {
        let (mut svc, pegin) = harness(crate::RelayFault::none().offline(&[1, 2, 3]));
        let err = svc.settle(&pegin).unwrap_err();
        assert!(
            matches!(err, CoordError::Invalid(_)),
            "below-threshold must fail loudly, got: {err:?}"
        );
        // Nothing settled, nothing broadcast.
        assert!(!svc.journal().is_settled(&pegin.txid_display, pegin.vout));
    }

    #[test]
    fn nonces_are_fresh_per_settlement() {
        let (mut svc, pegin1) = harness(crate::RelayFault::none());
        let rep1 = svc.settle(&pegin1).unwrap();
        let pegin2 = PegIn {
            txid_display: "ef".repeat(32),
            vout: 1,
            sats: 10_000_000,
        };
        let rep2 = svc.settle(&pegin2).unwrap();
        assert_ne!(
            rep1.attestation.attestation.nonce_hex,
            rep2.attestation.attestation.nonce_hex
        );
    }

    #[test]
    fn persisted_ceremony_feeds_service() {
        // The watch-mode path: ceremony loaded from disk.
        let dir = tempfile::tempdir().unwrap();
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        save_ceremony(dir.path(), config, &ops).unwrap();

        let group_pkg = load_group(dir.path()).unwrap();
        let mut loaded_ops = Vec::new();
        for i in 1..=5u16 {
            loaded_ops.push(frostgate_federation::load_operator(dir.path(), i).unwrap());
        }
        let relay = OperatorRelay::from_operators(loaded_ops, crate::RelayFault::none()).unwrap();

        let mut chain = MockChain {
            height: 2_900_000,
            ..Default::default()
        };
        let release_key = ReleaseKey::generate(&mut OsRng).unwrap();
        let pkh = frostgate_zcash::address::hash160_of_pubkey(&release_key.public_key_compressed());
        let vault_hex = hex_encode(&frostgate_zcash::address::p2pkh_script_pubkey(&pkh));
        let vault_txid = "ab".repeat(32);
        chain.fund(&vault_txid, 0, 100_000_000, &vault_hex);
        let dest_key = ReleaseKey::generate(&mut OsRng).unwrap();
        let dest_addr = frostgate_zcash::address::p2pkh_testnet(&dest_key.public_key_compressed());
        let cfg = ServiceConfig::demo(dest_addr, vault_txid, 0);
        let mut svc =
            CoordinatorService::new(group_pkg, 5, 3, relay, chain, release_key, cfg).unwrap();
        let pegin = PegIn {
            txid_display: "cd".repeat(32),
            vout: 0,
            sats: 50_000_000,
        };
        let rep = svc.settle(&pegin).unwrap();
        assert_eq!(rep.signers.len(), 3);
    }

    /// Live scan path: fresh ceremony -> real Esplora testnet3 query for the
    /// federation address. Ignored by default (network + external service).
    #[test]
    #[ignore]
    fn live_scan_fresh_federation_address_is_empty() {
        use frostgate_bitcoin::federation_address;
        use frostgate_federation::Coordinator as FedCoord;

        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        let coord = FedCoord::new(ops[0].public_key_package.clone());
        let addr = federation_address(&coord, bitcoin::Network::Testnet).unwrap();
        let utxos =
            frostgate_bitcoin::watcher::peg_in_utxos(BLOCKSTREAM_TESTNET, &addr.to_string())
                .unwrap();
        assert!(
            utxos.is_empty(),
            "fresh ceremony address must have no peg-ins"
        );
    }
}
