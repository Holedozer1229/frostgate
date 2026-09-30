//! FROST threshold signing sessions (RFC 9591, round 1 + round 2 + aggregation).
//!
//! Roles mirror the deployment: each [`OperatorSigner`] holds its DKG key
//! package and emits at most one signature share per commitment pair; the
//! [`Coordinator`] collects commitments, builds the [`frost::SigningPackage`],
//! collects shares, aggregates, and verifies.
//!
//! # Nonce discipline (hard constraint)
//! A `(D_i, E_i)` commitment pair is single-use. [`OperatorSigner::commit`]
//! refuses to issue a second commitment while one is outstanding, and
//! [`OperatorSigner::sign`] consumes the nonces, so a second signature from
//! the same commitment pair is structurally impossible. Fresh nonces are
//! drawn from the caller's CSPRNG on every [`commit`] call.
//!
//! # Coordinator trust (hard constraint)
//! Signers trust the coordinator for liveness and message integrity. The
//! coordinator in turn verifies every share at aggregation time; a bad share
//! aborts aggregation with the culprit identifiers attached
//! ([`frost::Error::InvalidSignatureShare`]), which the D6 adversarial demo
//! uses for attribution and exclusion.
//!
//! # Message handling (Taproot)
//! The `Secp256K1Sha256TR` ciphersuite feeds the signing message **directly**
//! into the BIP340-style challenge hash (`H2(R.x || vk.x || message)`); it
//! does not pre-hash. Therefore, on D3, the 32-byte Taproot sighash is passed
//! here as the message and the aggregated output is a valid BIP340 signature
//! over that sighash. D2 tests use fixed 32-byte messages to mirror this.

use std::collections::BTreeMap;

use frost_core::{
    self as frost, keys::PublicKeyPackage, round1, round2, Ciphersuite, Identifier, Signature,
    SigningPackage,
};
use frost_secp256k1_tr::keys::Tweak as _;

use super::{CeremonyError, FgSuite, OperatorKeys};

/// One operator's signing state for a single session.
///
/// Created from the operator's DKG [`super::OperatorKeys`]. Holds the
/// round-1 nonces between [`commit`](OperatorSigner::commit) and
/// [`sign`](OperatorSigner::sign); the nonces are consumed by `sign`.
pub struct OperatorSigner {
    identifier: Identifier<FgSuite>,
    key_package: frost::keys::KeyPackage<FgSuite>,
    /// Outstanding round-1 nonces. `Some` between commit and sign.
    pending_nonces: Option<round1::SigningNonces<FgSuite>>,
}

impl OperatorSigner {
    /// Wrap DKG key material as a signer.
    pub fn new(keys: OperatorKeys) -> Self {
        Self {
            identifier: keys.identifier,
            key_package: keys.key_package,
            pending_nonces: None,
        }
    }

    /// The signer's FROST identifier.
    pub fn identifier(&self) -> Identifier<FgSuite> {
        self.identifier
    }

    /// Round 1: draw fresh nonces and publish commitments.
    ///
    /// Fails if a commitment is already outstanding — a commitment pair is
    /// single-use and must be consumed by [`sign`](OperatorSigner::sign)
    /// before another may be issued.
    pub fn commit<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<round1::SigningCommitments<FgSuite>, CeremonyError> {
        if self.pending_nonces.is_some() {
            return Err(CeremonyError::Invalid(
                "commitment already outstanding: finish the current session first (nonce reuse is forbidden)".to_string(),
            ));
        }
        let (nonces, commitments) = round1::commit(self.key_package.signing_share(), rng);
        self.pending_nonces = Some(nonces);
        Ok(commitments)
    }

    /// Round 2: emit the signature share for the coordinator's package.
    ///
    /// The package must contain this signer's own commitment (it does when
    /// the coordinator built it from the commitments this signer published).
    /// Consumes the round-1 nonces: a second call fails.
    /// Round 2: emit the signature share for the coordinator's package.
    ///
    /// The package must contain this signer's own commitment (it does when
    /// the coordinator built it from the commitments this signer published).
    /// Consumes the round-1 nonces: a second call fails.
    pub fn sign(
        &mut self,
        signing_package: &SigningPackage<FgSuite>,
    ) -> Result<round2::SignatureShare<FgSuite>, CeremonyError> {
        let nonces = self.pending_nonces.take().ok_or_else(|| {
            CeremonyError::Invalid(
                "no outstanding commitment: call commit() before sign()".to_string(),
            )
        })?;
        Ok(round2::sign(signing_package, &nonces, &self.key_package)?)
    }

    /// Round 2 with a BIP341 Taproot tweak: emit the signature share for a
    /// key-path spend from the *tweaked* group key.
    ///
    /// `merkle_root = None` means pure key-path (no script tree): the tweak
    /// is `H_TapTweak(internal_key.x)`, exactly as Bitcoin consensus computes
    /// it. Consumes the round-1 nonces like [`sign`](OperatorSigner::sign).
    pub fn sign_with_tweak(
        &mut self,
        signing_package: &SigningPackage<FgSuite>,
        merkle_root: Option<&[u8]>,
    ) -> Result<round2::SignatureShare<FgSuite>, CeremonyError> {
        let nonces = self.pending_nonces.take().ok_or_else(|| {
            CeremonyError::Invalid(
                "no outstanding commitment: call commit() before sign_with_tweak()".to_string(),
            )
        })?;
        Ok(frost_secp256k1_tr::round2::sign_with_tweak(
            signing_package,
            &nonces,
            &self.key_package,
            merkle_root,
        )?)
    }
}

/// The coordinator: builds signing packages, aggregates shares, verifies.
pub struct Coordinator {
    public_key_package: PublicKeyPackage<FgSuite>,
}

impl Coordinator {
    /// Create a coordinator from the federation's public group package
    /// (e.g. loaded from the DKG ceremony's `group.json`).
    pub fn new(public_key_package: PublicKeyPackage<FgSuite>) -> Self {
        Self { public_key_package }
    }

    /// Build the signing package from the collected round-1 commitments.
    ///
    /// The commitment map must identify exactly the signers taking part in
    /// this session (at least `threshold` of them); the message is what gets
    /// signed — on D3, the 32-byte Taproot sighash.
    pub fn build_package(
        &self,
        commitments: BTreeMap<Identifier<FgSuite>, round1::SigningCommitments<FgSuite>>,
        message: &[u8],
    ) -> Result<SigningPackage<FgSuite>, CeremonyError> {
        if commitments.is_empty() {
            return Err(CeremonyError::Invalid(
                "cannot build a signing package with no commitments".to_string(),
            ));
        }
        Ok(SigningPackage::<FgSuite>::new(commitments, message))
    }

    /// Aggregate signature shares into the joint threshold signature.
    ///
    /// Every share is verified during aggregation; on the first bad share
    /// this returns [`frost::Error::InvalidSignatureShare`] carrying the
    /// culprit identifiers (used by the D6 adversarial demo).
    pub fn aggregate(
        &self,
        signing_package: &SigningPackage<FgSuite>,
        shares: &BTreeMap<Identifier<FgSuite>, round2::SignatureShare<FgSuite>>,
    ) -> Result<Signature<FgSuite>, CeremonyError> {
        Ok(frost::aggregate(
            signing_package,
            shares,
            &self.public_key_package,
        )?)
    }

    /// Like [`aggregate`](Coordinator::aggregate) but identifies **all**
    /// cheaters instead of stopping at the first.
    pub fn aggregate_identify_all(
        &self,
        signing_package: &SigningPackage<FgSuite>,
        shares: &BTreeMap<Identifier<FgSuite>, round2::SignatureShare<FgSuite>>,
    ) -> Result<Signature<FgSuite>, CeremonyError> {
        Ok(frost::aggregate_custom(
            signing_package,
            shares,
            &self.public_key_package,
            frost::CheaterDetection::AllCheaters,
        )?)
    }

    /// The BIP341-tweaked public group package for a key-path spend.
    ///
    /// `merkle_root = None` gives the pure key-path output key
    /// `Q = P + H_TapTweak(P.x)*G`. This is the key the on-chain P2TR
    /// address commits to, and the key threshold signatures must verify
    /// under when produced via [`aggregate_with_tweak`](Coordinator::aggregate_with_tweak).
    pub fn tweaked_public_package(&self, merkle_root: Option<&[u8]>) -> PublicKeyPackage<FgSuite> {
        self.public_key_package.clone().tweak(merkle_root)
    }

    /// Aggregate shares produced by
    /// [`sign_with_tweak`](OperatorSigner::sign_with_tweak) into a joint
    /// signature valid under the tweaked group key.
    pub fn aggregate_with_tweak(
        &self,
        signing_package: &SigningPackage<FgSuite>,
        shares: &BTreeMap<Identifier<FgSuite>, round2::SignatureShare<FgSuite>>,
        merkle_root: Option<&[u8]>,
    ) -> Result<Signature<FgSuite>, CeremonyError> {
        Ok(frost_secp256k1_tr::aggregate_with_tweak(
            signing_package,
            shares,
            &self.public_key_package,
            merkle_root,
        )?)
    }

    /// Verify a threshold signature against the group verifying key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature<FgSuite>,
    ) -> Result<(), CeremonyError> {
        Ok(self
            .public_key_package
            .verifying_key()
            .verify(message, signature)?)
    }

    /// Verify a tweaked (Taproot key-path) threshold signature against the
    /// tweaked group verifying key.
    pub fn verify_with_tweak(
        &self,
        message: &[u8],
        signature: &Signature<FgSuite>,
        merkle_root: Option<&[u8]>,
    ) -> Result<(), CeremonyError> {
        let tweaked = self.tweaked_public_package(merkle_root);
        Ok(tweaked.verifying_key().verify(message, signature)?)
    }

    /// Serialize a threshold signature to its 64-byte BIP340 encoding.
    pub fn signature_bytes(signature: &Signature<FgSuite>) -> Result<Vec<u8>, CeremonyError> {
        Ok(signature.serialize()?)
    }
}

/// Helper: is this a cheater-attribution error, and who are the culprits?
pub fn cheater_culprits(err: &CeremonyError) -> Option<Vec<Identifier<FgSuite>>> {
    match err {
        CeremonyError::Frost(frost::Error::InvalidSignatureShare { culprits }) => {
            Some(culprits.clone())
        }
        _ => None,
    }
}

// Silence the unused-import warning if the test build changes; the trait
// bound is documentation of intent.
#[allow(dead_code)]
fn _assert_ciphersuite<C: Ciphersuite>() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{load_group, load_operator, run_dkg, save_ceremony, CeremonyConfig};
    use rand::rngs::OsRng;

    /// Fixed 32-byte message, mirroring the D3 Taproot sighash usage.
    const MESSAGE: [u8; 32] = *b"FROSTGATE-D2-SIGNING-TEST-MSG-0!";

    /// Run DKG(5,3) and return signers for the given 1-based operator indices.
    fn ceremony_signers(idxs: &[u16]) -> (Coordinator, Vec<OperatorSigner>) {
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        let public_pkg = ops[0].public_key_package.clone();
        let signers = idxs
            .iter()
            .map(|i| {
                let op = ops
                    .iter()
                    .find(|o| {
                        Identifier::try_from(*i)
                            .map(|id| id == o.identifier)
                            .unwrap_or(false)
                    })
                    .expect("operator index must exist");
                OperatorSigner {
                    identifier: op.identifier,
                    key_package: op.key_package.clone(),
                    pending_nonces: None,
                }
            })
            .collect();
        (Coordinator::new(public_pkg), signers)
    }

    /// One full session: commit -> package -> sign -> aggregate -> verify.
    fn run_session(
        coord: &Coordinator,
        signers: &mut [OperatorSigner],
        message: &[u8],
    ) -> Result<Vec<u8>, CeremonyError> {
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
        Coordinator::signature_bytes(&sig)
    }

    #[test]
    fn signing_round_3_of_5_verifies_under_group_key() {
        let (coord, mut signers) = ceremony_signers(&[1, 2, 3]);
        let sig_bytes = run_session(&coord, &mut signers, &MESSAGE).unwrap();
        // BIP340 shape: exactly 64 bytes (R.x || s).
        assert_eq!(sig_bytes.len(), 64, "threshold signature must be 64 bytes");
    }

    #[test]
    fn signing_any_3_of_5_subset_works() {
        // Threshold means ANY 3 signers, not just the first 3.
        let (coord, mut signers) = ceremony_signers(&[2, 4, 5]);
        run_session(&coord, &mut signers, &MESSAGE).unwrap();
    }

    #[test]
    fn signing_fails_below_threshold() {
        let (coord, mut signers) = ceremony_signers(&[1, 2]);
        let mut commitments = BTreeMap::new();
        for s in signers.iter_mut() {
            commitments.insert(s.identifier(), s.commit(&mut OsRng).unwrap());
        }
        let package = coord.build_package(commitments, &MESSAGE).unwrap();
        // Below-threshold must fail somewhere in the pipeline: the signers
        // refuse to sign a package with fewer commitments than the threshold
        // (round2::sign errors), and aggregation would fail too. Collect
        // whatever shares we can and require the session to not complete.
        let mut shares = BTreeMap::new();
        let mut sign_failed = false;
        for s in signers.iter_mut() {
            match s.sign(&package) {
                Ok(share) => {
                    shares.insert(s.identifier(), share);
                }
                Err(_) => sign_failed = true,
            }
        }
        let aggregate_failed = coord.aggregate(&package, &shares).is_err();
        assert!(
            sign_failed || aggregate_failed,
            "a below-threshold session must not produce a valid signature"
        );
    }

    #[test]
    fn signing_rejects_wrong_message() {
        let (coord, mut signers) = ceremony_signers(&[1, 2, 3]);
        let mut commitments = BTreeMap::new();
        for s in signers.iter_mut() {
            commitments.insert(s.identifier(), s.commit(&mut OsRng).unwrap());
        }
        let package = coord.build_package(commitments, &MESSAGE).unwrap();
        let mut shares = BTreeMap::new();
        for s in signers.iter_mut() {
            shares.insert(s.identifier(), s.sign(&package).unwrap());
        }
        let sig = coord.aggregate(&package, &shares).unwrap();
        let mut wrong = MESSAGE;
        wrong[0] ^= 0xff;
        assert!(
            coord.verify(&wrong, &sig).is_err(),
            "signature must not verify under a different message"
        );
    }

    #[test]
    fn signing_detects_and_attributes_bad_share() {
        let (coord, mut signers) = ceremony_signers(&[1, 2, 3]);
        let mut commitments = BTreeMap::new();
        for s in signers.iter_mut() {
            commitments.insert(s.identifier(), s.commit(&mut OsRng).unwrap());
        }
        let package = coord.build_package(commitments, &MESSAGE).unwrap();

        // Cheater: operator 3 signs a package over a DIFFERENT message but
        // submits its share to this session. Its nonces match its published
        // commitment, so round2::sign succeeds — the share is simply wrong
        // for this session.
        let rogue_package = coord
            .build_package(
                package
                    .signing_commitments()
                    .iter()
                    .map(|(id, c)| (*id, *c))
                    .collect(),
                b"rogue-message-not-the-session-msg!",
            )
            .unwrap();

        let mut shares = BTreeMap::new();
        shares.insert(signers[0].identifier(), signers[0].sign(&package).unwrap());
        shares.insert(signers[1].identifier(), signers[1].sign(&package).unwrap());
        shares.insert(
            signers[2].identifier(),
            signers[2].sign(&rogue_package).unwrap(),
        );

        let err = coord.aggregate(&package, &shares).unwrap_err();
        let culprits = cheater_culprits(&err).expect("bad share must produce cheater attribution");
        assert_eq!(
            culprits,
            vec![signers[2].identifier()],
            "the culprit must be exactly the cheating operator"
        );

        // AllCheaters variant agrees.
        let err2 = coord.aggregate_identify_all(&package, &shares).unwrap_err();
        assert_eq!(
            cheater_culprits(&err2).unwrap(),
            vec![signers[2].identifier()]
        );
    }

    #[test]
    fn second_commit_while_outstanding_is_refused() {
        let (_coord, mut signers) = ceremony_signers(&[1]);
        let mut s = signers.pop().unwrap();
        s.commit(&mut OsRng).unwrap();
        // Second commit while one is outstanding: refused (nonce reuse
        // would be catastrophic).
        let err = s.commit(&mut OsRng).unwrap_err();
        assert!(
            matches!(err, CeremonyError::Invalid(_)),
            "double commit must be refused, got: {err:?}"
        );
    }

    #[test]
    fn double_sign_is_impossible() {
        let (coord, mut signers) = ceremony_signers(&[1, 2, 3]);
        let mut commitments = BTreeMap::new();
        for s in signers.iter_mut() {
            commitments.insert(s.identifier(), s.commit(&mut OsRng).unwrap());
        }
        let package = coord.build_package(commitments, &MESSAGE).unwrap();
        signers[0].sign(&package).unwrap();
        // Nonces were consumed: signing again fails.
        assert!(signers[0].sign(&package).is_err());
        // And a fresh commit works again for the next session (fresh nonces).
        signers[0].commit(&mut OsRng).unwrap();
    }

    #[test]
    fn signing_end_to_end_via_persisted_ceremony() {
        // D1 persistence path -> D2 signing: save, reload operators 1..=3
        // from disk, run a session, verify under the reloaded group package.
        let dir = tempfile::tempdir().unwrap();
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        save_ceremony(dir.path(), config, &ops).unwrap();

        let group_pkg = load_group(dir.path()).unwrap();
        let coord = Coordinator::new(group_pkg);
        let mut signers: Vec<OperatorSigner> = (1..=3u16)
            .map(|i| OperatorSigner::new(load_operator(dir.path(), i).unwrap()))
            .collect();
        let sig_bytes = run_session(&coord, &mut signers, &MESSAGE).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn share_commitment_identifier_mismatch_fails() {
        let (coord, mut signers) = ceremony_signers(&[1, 2, 3]);
        let mut commitments = BTreeMap::new();
        for s in signers.iter_mut() {
            commitments.insert(s.identifier(), s.commit(&mut OsRng).unwrap());
        }
        let package = coord.build_package(commitments, &MESSAGE).unwrap();
        // Drop one share: identifiers no longer match the package.
        let mut shares = BTreeMap::new();
        for s in signers.iter_mut().take(2) {
            shares.insert(s.identifier(), s.sign(&package).unwrap());
        }
        assert!(coord.aggregate(&package, &shares).is_err());
    }
}
