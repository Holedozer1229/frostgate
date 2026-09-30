//! Operator relay: the coordinator's view of the operator set.
//!
//! In production this is a network transport with authenticated channels to
//! five operator daemons. Here it is an in-process mesh over
//! [`frostgate_federation::OperatorSigner`]s with **fault injection** for the
//! D6 adversarial demo:
//! - [`RelayFault::offline`]: operators that never answer (the 2-offline demo).
//! - [`RelayFault::corrupt_share`]: one operator signs a rogue message but
//!   submits the share to the real session (the malicious-share demo).
//!
//! The signing math is identical to the networked case; only the transport
//! is simulated.

use std::collections::BTreeMap;

use frostgate_federation::{
    round1, round2, CeremonyError, FgSuite, Identifier, OperatorKeys, OperatorSigner,
    SigningPackage,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("ceremony error: {0}")]
    Ceremony(#[from] CeremonyError),
    #[error("relay error: {0}")]
    Invalid(String),
}

/// Faults the relay injects into an otherwise honest operator set.
#[derive(Debug, Clone, Default)]
pub struct RelayFault {
    /// 1-based operator indices that never respond.
    pub offline: Vec<u16>,
    /// 1-based operator index whose share is corrupted (signs a rogue
    /// message, submits to the real session).
    pub corrupt_share: Option<u16>,
}

impl RelayFault {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn offline(mut self, ids: &[u16]) -> Self {
        self.offline = ids.to_vec();
        self
    }

    pub fn corrupt_share(mut self, id: u16) -> Self {
        self.corrupt_share = Some(id);
        self
    }
}

/// In-process operator mesh with fault injection.
pub struct OperatorRelay {
    signers: BTreeMap<u16, OperatorSigner>,
    identifiers: BTreeMap<u16, Identifier<FgSuite>>,
    fault: RelayFault,
}

impl OperatorRelay {
    /// Build the relay from DKG output. `ops` must be the full operator set
    /// (identifiers are recovered as 1-based indices).
    pub fn from_operators(ops: Vec<OperatorKeys>, fault: RelayFault) -> Result<Self, RelayError> {
        let n = ops.len() as u16;
        let mut signers = BTreeMap::new();
        let mut identifiers = BTreeMap::new();
        for op in ops {
            let idx =
                frostgate_federation::identifier_index(&op.identifier, n).ok_or_else(|| {
                    RelayError::Invalid("operator identifier out of ceremony range".to_string())
                })?;
            identifiers.insert(idx, op.identifier);
            signers.insert(idx, OperatorSigner::new(op));
        }
        Ok(Self {
            signers,
            identifiers,
            fault,
        })
    }

    /// 1-based indices of operators that answer (fault.offline excluded).
    pub fn online_ids(&self) -> Vec<u16> {
        self.signers
            .keys()
            .filter(|id| !self.fault.offline.contains(id))
            .copied()
            .collect()
    }

    /// Round 1: collect commitments from `ids`. Offline operators are an
    /// error here — the coordinator is expected to select from
    /// [`online_ids`](OperatorRelay::online_ids).
    pub fn commit<R: RngCore + CryptoRng>(
        &mut self,
        ids: &[u16],
        rng: &mut R,
    ) -> Result<BTreeMap<Identifier<FgSuite>, round1::SigningCommitments<FgSuite>>, RelayError>
    {
        let mut out = BTreeMap::new();
        for id in ids {
            if self.fault.offline.contains(id) {
                return Err(RelayError::Invalid(format!(
                    "operator {id} is offline (fault injection)"
                )));
            }
            let signer = self
                .signers
                .get_mut(id)
                .ok_or_else(|| RelayError::Invalid(format!("unknown operator index {id}")))?;
            let commitments = signer.commit(rng)?;
            let ident = self.identifiers[id];
            out.insert(ident, commitments);
        }
        Ok(out)
    }

    /// Round 2: collect signature shares for `package`.
    ///
    /// The corrupt-share operator (if any) signs a *rogue* package carrying
    /// the same commitments but a different message, then submits that share
    /// to this session — exactly the attack the D6 demo detects.
    pub fn sign(
        &mut self,
        package: &SigningPackage<FgSuite>,
    ) -> Result<BTreeMap<Identifier<FgSuite>, round2::SignatureShare<FgSuite>>, RelayError> {
        let rogue_package: Option<SigningPackage<FgSuite>> = self.fault.corrupt_share.map(|_| {
            let commitments = package
                .signing_commitments()
                .iter()
                .map(|(id, c)| (*id, *c))
                .collect();
            SigningPackage::<FgSuite>::new(commitments, b"frostgate-rogue-message")
        });

        let mut out = BTreeMap::new();
        for (id, signer) in self.signers.iter_mut() {
            let ident = self.identifiers[id];
            if !package.signing_commitments().contains_key(&ident) {
                continue; // not selected for this session
            }
            let corrupt = self.fault.corrupt_share == Some(*id);
            let share = if corrupt {
                signer.sign(rogue_package.as_ref().expect("rogue package built"))?
            } else {
                signer.sign(package)?
            };
            out.insert(ident, share);
        }
        Ok(out)
    }

    /// Identifier for a 1-based operator index (for attribution mapping).
    pub fn identifier_of(&self, index: u16) -> Option<Identifier<FgSuite>> {
        self.identifiers.get(&index).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frostgate_federation::{run_dkg, CeremonyConfig};
    use rand::rngs::OsRng;

    fn relay_with(fault: RelayFault) -> OperatorRelay {
        let config = CeremonyConfig::new(5, 3).unwrap();
        let ops = run_dkg(config, OsRng).unwrap();
        OperatorRelay::from_operators(ops, fault).unwrap()
    }

    #[test]
    fn online_ids_excludes_offline() {
        let r = relay_with(RelayFault::none().offline(&[1, 2]));
        assert_eq!(r.online_ids(), vec![3, 4, 5]);
    }

    #[test]
    fn commit_to_offline_operator_fails() {
        let mut r = relay_with(RelayFault::none().offline(&[2]));
        let err = r.commit(&[2], &mut OsRng).unwrap_err();
        assert!(matches!(err, RelayError::Invalid(_)));
    }
}
