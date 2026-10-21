//! Independent small integer transition oracle with no evaluator or delta-builder calls.

use crate::{AcceptedEffect, AccountEffect, EffectRecord, LogicalState, NoteAppend};
use houseki_types::{
    Amount, ExecutionOutcome, ExecutionRejectionReason as R, NoteCommitment, NotePosition,
    Occurrence, RewardAccountId, TransactionEnvelope, WithdrawalNonce,
};
use std::collections::{BTreeMap, BTreeSet};

/// Small unoptimized public-state model for bounded deterministic scenario permutations.
pub(crate) struct ReferenceModel {
    /// Integer pool accounting independent of native amount arithmetic helpers.
    pub(crate) pool: u128,

    /// Complete insertion-order note instances.
    pub(crate) leaves: Vec<NoteCommitment>,

    /// Complete spent markers with independent deterministic ordering.
    pub(crate) spent: BTreeSet<[u8; 64]>,

    /// Integer balance/nonce pairs keyed by complete registered account identity.
    pub(crate) accounts: BTreeMap<[u8; 64], (u128, u64)>,

    /// Immutable author-to-beneficiary mapping.
    beneficiaries: BTreeMap<[u8; 64], [u8; 64]>,
}

impl ReferenceModel {
    /// Copies only public initial scalar values and lists into the independent model.
    pub(crate) fn new(state: &LogicalState) -> Self {
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

    /// Executes valid-context small inputs directly and derives expected public effect records.
    pub(crate) fn step(&mut self, occurrence: &Occurrence) -> (ExecutionOutcome, EffectRecord) {
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
                    let fee = (b.inputs().input_count() + b.outputs().output_count()) as u128;
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
