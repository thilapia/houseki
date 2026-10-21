//! Deterministic state decisions over already authorized occurrences.

mod context;
mod decision;
mod delta;
mod error;
mod payment;
mod withdrawal;

pub(crate) use decision::Decision;
pub(crate) use delta::TransactionDelta;
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

/// Independent model comparisons and canonical ordered retry scenarios.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    /// Independent integer state and effects for this module’s ordered scenarios.
    mod model {
        use crate::{AcceptedEffect, AccountEffect, EffectRecord, LogicalState, NoteAppend};
        use houseki_types::{
            Amount, ExecutionOutcome, ExecutionRejectionReason as R, NoteCommitment, NotePosition,
            Occurrence, RewardAccountId, TransactionEnvelope, WithdrawalNonce,
        };
        use std::collections::{BTreeMap, BTreeSet};

        /// Small unoptimized public state model for bounded deterministic scenario
        /// permutations.
        pub(super) struct ReferenceModel {
            /// Integer pool accounting independent of native amount arithmetic
            /// helpers.
            pub(super) pool: u128,

            /// Complete insertion order note instances.
            pub(super) leaves: Vec<NoteCommitment>,

            /// Complete spent markers with independent deterministic ordering.
            spent: BTreeSet<[u8; 64]>,

            /// Integer balance/nonce pairs keyed by complete registered account
            /// identity.
            pub(super) accounts: BTreeMap<[u8; 64], (u128, u64)>,

            /// Immutable author to beneficiary mapping.
            beneficiaries: BTreeMap<[u8; 64], [u8; 64]>,
        }

        impl ReferenceModel {
            /// Copies only public initial scalar values and lists into the
            /// independent model.
            pub(super) fn new(state: &LogicalState) -> Self {
                Self {
                    pool: state.pool().atoms(),
                    leaves: state.leaves().to_vec(),
                    spent: state.spent().map(|n| n.into_bytes()).collect(),
                    accounts: state
                        .accounts()
                        .map(|(id, a)| (*id, (a.balance().atoms(), a.next_nonce().value())))
                        .collect(),
                    beneficiaries: state
                        .committee()
                        .map(|c| (c.validator().into_bytes(), c.reward_account().into_bytes()))
                        .collect(),
                }
            }

            /// Executes valid context small inputs directly and derives
            /// expected public effect records.
            pub(super) fn step(
                &mut self,
                occurrence: &Occurrence,
            ) -> (ExecutionOutcome, EffectRecord) {
                let beneficiary = self.beneficiaries[occurrence.vertex_author().as_bytes()];
                let old_pool = self.pool;
                let mut accounts = vec![];
                let mut appends = vec![];
                let mut nullifiers = vec![];
                let rejection = match occurrence.envelope() {
                    TransactionEnvelope::Payment(e) => {
                        let b = e.body();
                        if b.inputs()
                            .nullifiers()
                            .iter()
                            .any(|n| self.spent.contains(n.as_bytes()))
                        {
                            Some(R::SpentNullifier)
                        } else {
                            let fee =
                                (b.inputs().input_count() + b.outputs().output_count()) as u128;
                            let before = self.accounts[&beneficiary];
                            self.accounts.get_mut(&beneficiary).unwrap().0 += fee;
                            self.pool -= fee;
                            accounts.push(account_effect(
                                beneficiary,
                                before,
                                self.accounts[&beneficiary],
                            ));
                            for &n in b.inputs().nullifiers() {
                                self.spent.insert(n.into_bytes());
                                nullifiers.push(n);
                            }

                            for output in b.outputs().outputs() {
                                let position = self.leaves.len() as u64;
                                self.leaves.push(output.commitment());
                                appends.push(NoteAppend {
                                    position: NotePosition::new(position),
                                    commitment: output.commitment(),
                                });
                            }

                            None
                        }
                    }
                    TransactionEnvelope::RewardWithdrawal(e) => {
                        let b = e.body();
                        let id = b.reward_account_id().into_bytes();
                        let before = self.accounts[&id];
                        let amount = b.public_amount().atoms();
                        let fee = 1;
                        if before.1 != b.nonce().value() {
                            Some(R::WrongNonce)
                        } else if before.1 == u64::MAX {
                            Some(R::NonceExhausted)
                        } else if before.0 < amount + fee {
                            Some(R::InsufficientBalance)
                        } else {
                            let beneficiary_before = self.accounts[&beneficiary];
                            self.accounts
                                .insert(id, (before.0 - amount - fee, before.1 + 1));
                            self.accounts.get_mut(&beneficiary).unwrap().0 += fee;
                            accounts.push(account_effect(id, before, self.accounts[&id]));
                            if id != beneficiary {
                                accounts.push(account_effect(
                                    beneficiary,
                                    beneficiary_before,
                                    self.accounts[&beneficiary],
                                ));
                            }

                            accounts.sort_unstable_by_key(|a| a.account_id.into_bytes());
                            let position = self.leaves.len() as u64;
                            self.leaves.push(b.output().commitment());
                            appends.push(NoteAppend {
                                position: NotePosition::new(position),
                                commitment: b.output().commitment(),
                            });

                            self.pool += amount;
                            None
                        }
                    }
                };

                let accepted = if rejection.is_none() {
                    Some(AcceptedEffect {
                        nullifiers,
                        appends,
                        accounts,
                        before_pool: Amount::from_atoms(old_pool).unwrap(),
                        after_pool: Amount::from_atoms(self.pool).unwrap(),
                    })
                } else {
                    None
                };

                (
                    rejection.map_or(ExecutionOutcome::Accepted, ExecutionOutcome::Rejected),
                    EffectRecord {
                        vertex_id: occurrence.vertex_id(),
                        transaction_index: occurrence.transaction_index(),
                        accepted,
                    },
                )
            }
        }

        /// Forms an independently computed complete account replacement record.
        fn account_effect(id: [u8; 64], before: (u128, u64), after: (u128, u64)) -> AccountEffect {
            AccountEffect {
                account_id: RewardAccountId::from_bytes(id),
                before_balance: Amount::from_atoms(before.0).unwrap(),
                before_nonce: WithdrawalNonce::new(before.1),
                after_balance: Amount::from_atoms(after.0).unwrap(),
                after_nonce: WithdrawalNonce::new(after.1),
            }
        }
    }

    use super::*;
    use crate::test_support::{payment, payment_body, trusted_manifest};
    use crate::{EffectRecord, LogicalState, validate_bootstrap};
    use houseki_proofs::ProofContext;
    use houseki_types::{
        Amount, CheckpointSequence, EncodedMlDsa87Signature, EncodedTransactionProof,
        ExecutionOutcome, ExecutionRejectionReason as R, FeeScheduleId, Occurrence, ProofProfileId,
        RewardAccountId, RewardWithdrawalBody, RewardWithdrawalEnvelope, TransactionContext,
        TransactionEnvelope, ValidatorId, VertexId, WithdrawalNonce,
    };
    use model::ReferenceModel;

    /// Evaluates a synthetic checked occurrence and applies only its complete accepted
    /// delta.
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

    /// First successful conflicting input earns one fee and later copies have empty
    /// effects.
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

    /// Complete public effects match an independent integer model through fixed seed
    /// permutations.
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

    /// Authors mapped to the same account accumulate both independently ordered
    /// credits.
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

    /// Constructs an understood withdrawal without creating any public authorization
    /// bypass.
    fn withdrawal(
        state: &LogicalState,
        index: u64,
        source: RewardAccountId,
        nonce: u64,
        author: ValidatorId,
    ) -> Occurrence {
        let base = payment_body(1, 1);
        let c = base.context();
        let context = TransactionContext::new(
            state.network(),
            c.protocol_version(),
            ProofProfileId::new(0xffff0007),
            FeeScheduleId::new(0xffff0001),
            c.validity_checkpoint_range(),
        );
        let body = RewardWithdrawalBody::new(
            context,
            source,
            state
                .account(source)
                .unwrap()
                .withdrawal_authority()
                .clone(),
            WithdrawalNonce::new(nonce),
            Amount::from_atoms(3).unwrap(),
            Amount::from_atoms(1).unwrap(),
            base.outputs().outputs()[0].clone(),
        )
        .unwrap();
        Occurrence::new(
            VertexId::from_bytes([1; 64]),
            author,
            state.committee_context(),
            index,
            RewardWithdrawalEnvelope::new(
                body,
                EncodedTransactionProof::new(vec![], 0).unwrap(),
                EncodedMlDsa87Signature::from_bytes([0; 4627]),
            )
            .into(),
        )
    }
}
