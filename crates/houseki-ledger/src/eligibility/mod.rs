//! Whole-unit recognition and local authorization before any state receipt exists.

mod anchor;
mod context;
mod error;
mod occurrence;
mod unit;

pub use error::UnitPreparationError;
pub(crate) use occurrence::AuthorizedOccurrence;
pub use unit::AuthorizedUnit;

use crate::{LedgerEngine, ParentSnapshot, VerifiedOrderUnit};
use houseki_crypto::MlDsa87VerificationKey;
use houseki_proofs::{ProofRuntime, verify_payment, verify_reward_withdrawal};
use houseki_types::TransactionEnvelope;

impl LedgerEngine {
    /// Checks every complete source envelope before issuing owned local unit authorization.
    ///
    /// Verification is serial under one caller-owned runtime and never creates a state receipt.
    ///
    /// # Errors
    ///
    /// Reports missing trusted metadata, unknown claims, mismatched immutable authorities,
    /// invalid proofs/signatures and operational verifier failures without partial authorization.
    pub fn authorize_unit(
        &self,
        parent: &ParentSnapshot,
        unit: VerifiedOrderUnit,
        runtime: &ProofRuntime,
    ) -> Result<AuthorizedUnit, UnitPreparationError> {
        authorize_checked(parent, unit, |occurrence, context, anchor| {
            match occurrence.envelope() {
                TransactionEnvelope::Payment(e) => {
                    let anchor = anchor.ok_or(UnitPreparationError::Integrity)?;
                    let _verified = verify_payment(runtime, e.body(), &anchor, e.proof(), context)?;
                }
                TransactionEnvelope::RewardWithdrawal(e) => {
                    let _verified =
                        verify_reward_withdrawal(runtime, e.body(), e.proof(), context)?;
                    MlDsa87VerificationKey::from_encoded(e.body().withdrawal_public_key())
                        .verify_reward_withdrawal(e.body(), e.signature(), context.body_limits())?;
                }
            }
            Ok(())
        })
    }
}

/// Performs exact local composition, with a private verifier adapter for operational tests.
fn authorize_checked(
    parent: &ParentSnapshot,
    unit: VerifiedOrderUnit,
    mut verify: impl FnMut(
        &houseki_types::Occurrence,
        &houseki_proofs::ProofContext,
        Option<houseki_types::NoteTreeAnchor>,
    ) -> Result<(), UnitPreparationError>,
) -> Result<AuthorizedUnit, UnitPreparationError> {
    let dependencies = context::resolve_dependencies(parent, &unit)?;
    for (index, occurrence) in unit.occurrences().iter().enumerate() {
        verify(
            occurrence,
            &dependencies.contexts[index],
            dependencies.anchors[index],
        )?;
    }
    Ok(AuthorizedUnit::checked(unit, dependencies))
}

/// Creates private synthetic state-test evidence while preserving all real dependency resolution.
#[cfg(all(test, feature = "experimental-profiles"))]
pub(crate) fn authorize_for_test(
    parent: &ParentSnapshot,
    unit: VerifiedOrderUnit,
) -> Result<AuthorizedUnit, UnitPreparationError> {
    authorize_checked(parent, unit, |_, _, _| Ok(()))
}

/// Real proof/signature whole-unit composition tests.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::{fixture_source_for, seed_fixture};
    use crate::{FixtureOrderVerifier, LedgerEngine};
    use houseki_proofs::ProofRuntime;
    use houseki_types::{
        EncodedTransactionProof, Occurrence, RewardWithdrawalEnvelope, TransactionEnvelope,
    };

    /// Copies the exact source envelope into a distinct genuine origin position.
    fn at(original: &Occurrence, index: u64) -> Occurrence {
        Occurrence::new(
            original.vertex_id(),
            original.vertex_author(),
            original.committee_context(),
            index,
            original.envelope().clone(),
        )
    }

    /// Mutates only supplied proof bytes while preserving the signed body.
    fn bad_proof(original: &Occurrence, index: u64) -> Occurrence {
        let TransactionEnvelope::RewardWithdrawal(e) = original.envelope() else {
            panic!("withdrawal seed")
        };
        let mut proof = e.proof().as_bytes().to_vec();
        proof[0] ^= 1;
        Occurrence::new(
            original.vertex_id(),
            original.vertex_author(),
            original.committee_context(),
            index,
            RewardWithdrawalEnvelope::new(
                e.body().clone(),
                EncodedTransactionProof::new(proof, 2097152).unwrap(),
                e.signature().clone(),
            )
            .into(),
        )
    }

    /// A valid first proof never issues partial evidence when a later complete envelope fails.
    #[test]
    fn all_occurrences_required_before_authorization() {
        let (m, original) = seed_fixture();
        let (parent, manifest, raw) =
            fixture_source_for(m, vec![vec![at(&original, 0), bad_proof(&original, 1)]]);
        let unit = FixtureOrderVerifier::new(manifest, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();
        assert!(matches!(
            LedgerEngine::new().authorize_unit(&parent, unit, &ProofRuntime::new()),
            Err(UnitPreparationError::InvalidProof(_))
        ));
        assert!(parent.receipts().is_empty());
    }

    /// Authorization owns every byte after temporary proof evidence and input copies disappear.
    #[test]
    fn owned_authorization_retains_exact_envelopes() {
        let (m, original) = seed_fixture();
        let (parent, manifest, raw) = fixture_source_for(m, vec![vec![original.clone()]]);
        let unit = FixtureOrderVerifier::new(manifest, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();
        let expected = unit.canonical_bytes().to_vec();
        let authorized = LedgerEngine::new()
            .authorize_unit(&parent, unit, &ProofRuntime::new())
            .unwrap();
        drop(raw);
        assert_eq!(authorized.order_unit().canonical_bytes(), expected);
        assert_eq!(authorized.order_unit().occurrences(), &[original]);
        assert!(authorized.occurrence(0).is_some());
        assert!(authorized.occurrence(1).is_none());
    }

    /// A valid output proof with an invalid required source signature is not authorization.
    #[test]
    fn authority_signature_and_output_proof_are_all_required() {
        let (m, original) = seed_fixture();
        let TransactionEnvelope::RewardWithdrawal(e) = original.envelope() else {
            panic!("withdrawal seed")
        };
        let wrong = Occurrence::new(
            original.vertex_id(),
            original.vertex_author(),
            original.committee_context(),
            0,
            RewardWithdrawalEnvelope::new(
                e.body().clone(),
                e.proof().clone(),
                houseki_types::EncodedMlDsa87Signature::from_bytes([0; 4627]),
            )
            .into(),
        );
        let (parent, manifest, raw) = fixture_source_for(m, vec![vec![wrong]]);
        let unit = FixtureOrderVerifier::new(manifest, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();
        assert!(matches!(
            LedgerEngine::new().authorize_unit(&parent, unit, &ProofRuntime::new()),
            Err(UnitPreparationError::Signature(_))
        ));
    }
    /// Mutable balances and nonces do not invalidate evidence, while fixed authority changes do.
    #[test]
    fn authorization_compatibility_ignores_only_evolving_state() {
        let (m, original) = seed_fixture();
        let (mut parent, manifest, raw) = fixture_source_for(m, vec![vec![original]]);
        let unit = FixtureOrderVerifier::new(manifest, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();
        let authorized = LedgerEngine::new()
            .authorize_unit(&parent, unit, &ProofRuntime::new())
            .unwrap();
        let image = std::sync::Arc::get_mut(&mut parent.image).unwrap();
        let record = std::sync::Arc::get_mut(&mut image.current).unwrap();
        let account = record.state.accounts.values_mut().next().unwrap();
        *account = houseki_types::RewardAccount::new(
            account.withdrawal_authority().clone(),
            houseki_types::Amount::from_atoms(99).unwrap(),
            houseki_types::WithdrawalNonce::new(1),
        );
        record.state.pool = houseki_types::Amount::from_atoms(1).unwrap();
        authorized.require_compatible(&parent).unwrap();
        let image = std::sync::Arc::get_mut(&mut parent.image).unwrap();
        let record = std::sync::Arc::get_mut(&mut image.current).unwrap();
        let account = record.state.accounts.values_mut().next().unwrap();
        *account = houseki_types::RewardAccount::new(
            houseki_types::EncodedMlDsa87PublicKey::from_bytes([99; 2592]),
            account.balance(),
            account.next_nonce(),
        );
        assert!(matches!(
            authorized.require_compatible(&parent),
            Err(UnitPreparationError::Integrity)
        ));
    }
    /// Busy and unavailable local verification abort before any further envelope or receipt.
    #[test]
    fn operational_verifier_failures_abort_unit() {
        for unavailable in [false, true] {
            let (m, original) = seed_fixture();
            let (parent, manifest, raw) =
                fixture_source_for(m, vec![vec![at(&original, 0), at(&original, 1)]]);
            let unit = FixtureOrderVerifier::new(manifest, &parent)
                .unwrap()
                .verify_unit(raw[0].clone())
                .unwrap();
            let mut calls = 0;
            let result = authorize_checked(&parent, unit, |_, _, _| {
                calls += 1;
                Err(if unavailable {
                    houseki_proofs::VerifyError::BackendUnavailable
                } else {
                    houseki_proofs::VerifyError::Busy
                }
                .into())
            });
            assert!(matches!(result, Err(UnitPreparationError::Operational(_))));
            assert_eq!(calls, 1);
            assert!(parent.receipts().is_empty());
        }
    }
}
