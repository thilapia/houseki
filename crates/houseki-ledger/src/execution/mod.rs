//! Deterministic state decisions over already authorized occurrences.

mod common;
mod delta;
mod error;
mod payment;
mod withdrawal;

pub(crate) use delta::{Decision, TransactionDelta};
pub use error::ExecutionError;

use crate::eligibility::AuthorizedOccurrence;
use crate::{CheckpointRules, WorkingState};
use houseki_types::TransactionEnvelope;

/// Dispatches a locally authorized occurrence under one fixed checkpoint context.
pub(crate) fn evaluate(
    rules: &CheckpointRules,
    state: &WorkingState,
    occurrence: &AuthorizedOccurrence<'_>,
) -> Result<Decision, ExecutionError> {
    if state.is_poisoned() {
        return Err(ExecutionError::Integrity);
    }
    match occurrence.occurrence().envelope() {
        TransactionEnvelope::Payment(_) => payment::evaluate_payment(rules, state, occurrence),
        TransactionEnvelope::RewardWithdrawal(_) => {
            withdrawal::evaluate_withdrawal(rules, state, occurrence)
        }
    }
}

/// Independent model comparisons and canonical ordered-retry scenarios.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::{
        execution::{payment, withdrawal},
        model::ReferenceModel,
        trusted_manifest,
    };
    use crate::{EffectRecord, validate_bootstrap};
    use houseki_proofs::ProofContext;
    use houseki_types::{
        CheckpointSequence, ExecutionOutcome, ExecutionRejectionReason as R, Occurrence,
        RewardAccountId, TransactionEnvelope, ValidatorId,
    };

    /// Evaluates a synthetic checked occurrence and applies only its complete accepted delta.
    fn run(
        rules: &CheckpointRules,
        working: &mut WorkingState,
        occurrence: &Occurrence,
    ) -> (ExecutionOutcome, EffectRecord) {
        let context = match occurrence.envelope() {
            TransactionEnvelope::Payment(e) => e.body().context(),
            TransactionEnvelope::RewardWithdrawal(e) => e.body().context(),
        };
        let context = ProofContext::new(context).unwrap();
        let anchor = matches!(occurrence.envelope(), TransactionEnvelope::Payment(_))
            .then_some(rules.eligible_anchors()[0]);
        let checked =
            crate::eligibility::AuthorizedOccurrence::for_test(occurrence, &context, anchor);
        match evaluate(rules, working, &checked).unwrap() {
            Decision::Accept(delta) => (ExecutionOutcome::Accepted, working.apply(delta).unwrap()),
            Decision::Reject(reason) => (
                ExecutionOutcome::Rejected(reason),
                EffectRecord {
                    vertex_id: occurrence.vertex_id(),
                    transaction_index: occurrence.transaction_index(),
                    accepted: None,
                },
            ),
        }
    }

    /// A rejected early copy can succeed after an intervening accepted fee credit.
    #[test]
    fn failed_early_copy_succeeds_after_fee_credit() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let mut working = WorkingState::reconstruct(parent.state()).unwrap();
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();
        let id = RewardAccountId::from_bytes(*parent.state().accounts().next().unwrap().0);
        let author = ValidatorId::from_bytes([5; 64]);
        let occurrences = [
            withdrawal(parent.state(), 0, id, 0, author),
            payment(parent.state(), 1, 10, author),
            withdrawal(parent.state(), 2, id, 0, author),
            withdrawal(parent.state(), 3, id, 0, author),
        ];
        let results: Vec<_> = occurrences
            .iter()
            .map(|o| run(&rules, &mut working, o).0)
            .collect();
        assert_eq!(
            results,
            vec![
                ExecutionOutcome::Rejected(R::InsufficientBalance),
                ExecutionOutcome::Accepted,
                ExecutionOutcome::Accepted,
                ExecutionOutcome::Rejected(R::WrongNonce)
            ]
        );
        assert_eq!(working.state().pool().atoms(), 99);
    }

    /// First successful conflicting input earns one fee and later copies have empty effects.
    #[test]
    fn conflicts_pay_only_once() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();
        let mut working = WorkingState::reconstruct(parent.state()).unwrap();
        let author = ValidatorId::from_bytes([5; 64]);
        assert_eq!(
            run(
                &rules,
                &mut working,
                &payment(parent.state(), 0, 10, author)
            )
            .0,
            ExecutionOutcome::Accepted
        );
        let (outcome, effect) = run(
            &rules,
            &mut working,
            &payment(parent.state(), 1, 10, author),
        );
        assert_eq!(outcome, ExecutionOutcome::Rejected(R::SpentNullifier));
        assert!(effect.accepted.is_none());
        assert_eq!(working.state().pool().atoms(), 96);
    }

    /// Complete public effects match an independent integer model through fixed-seed permutations.
    #[test]
    fn deterministic_scenarios_match_independent_model() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();
        let id = RewardAccountId::from_bytes(*parent.state().accounts().next().unwrap().0);
        let author = ValidatorId::from_bytes([5; 64]);
        let mut seed = 0x20261021_u64;
        for _case in 0..16 {
            let mut working = WorkingState::reconstruct(parent.state()).unwrap();
            let mut model = ReferenceModel::new(parent.state());
            for index in 0..12 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let o = if seed & 1 == 0 {
                    payment(
                        parent.state(),
                        index,
                        ((seed >> 8) % 4) as u8 * 2 + 10,
                        author,
                    )
                } else {
                    withdrawal(parent.state(), index, id, (seed >> 12) % 3, author)
                };
                let expected = model.step(&o);
                let actual = run(&rules, &mut working, &o);
                assert_eq!(actual, expected);
                assert_eq!(working.state().pool().atoms(), model.pool);
                assert_eq!(working.state().leaves(), model.leaves);
                for (id, a) in working.state().accounts() {
                    assert_eq!(
                        (a.balance().atoms(), a.next_nonce().value()),
                        model.accounts[id]
                    );
                }
            }
        }
    }
    /// Authors mapped to the same account accumulate both independently ordered credits.
    #[test]
    fn shared_beneficiary_preserves_both_credits() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();
        let mut working = WorkingState::reconstruct(parent.state()).unwrap();
        let id = RewardAccountId::from_bytes(*parent.state().accounts().next().unwrap().0);
        let other = ValidatorId::from_bytes([6; 64]);
        std::sync::Arc::make_mut(&mut working.state.committee).insert(
            other.into_bytes(),
            crate::CommitteeEntry::new(other, 1, id, vec![]),
        );
        let first = payment(parent.state(), 0, 10, ValidatorId::from_bytes([5; 64]));
        let second = payment(parent.state(), 1, 20, other);
        assert_eq!(
            run(&rules, &mut working, &first).0,
            ExecutionOutcome::Accepted
        );
        assert_eq!(
            run(&rules, &mut working, &second).0,
            ExecutionOutcome::Accepted
        );
        assert_eq!(working.state().account(id).unwrap().balance().atoms(), 8);
        assert_eq!(working.state().pool().atoms(), 92);
    }
}
