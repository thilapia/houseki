//! Complete preflighted delta application to disposable state only.

use super::{StateError, WorkingState};
use crate::EffectRecord;
use crate::execution::TransactionDelta;
#[cfg(all(test, feature = "experimental-profiles"))]
use crate::test_support::{FailurePoint, hit};
use houseki_types::RewardAccount;

impl WorkingState {
    /// Applies a complete delta after validating every before value and reference
    /// bound.
    ///
    /// Any local error poisons this disposable owner so the enclosing checkpoint must
    /// abort.
    pub(crate) fn apply(&mut self, delta: TransactionDelta) -> Result<EffectRecord, StateError> {
        if self.poisoned {
            return Err(StateError::Integrity);
        }

        let result = self.apply_inner(delta);
        if result.is_err() {
            self.poisoned = true;
        }

        result
    }

    /// Performs only owned working state writes after all before value checks succeed.
    #[cfg_attr(
        not(all(test, feature = "experimental-profiles")),
        allow(
            clippy::unused_enumerate_index,
            reason = "Original operation indices select private test fault boundaries."
        )
    )]
    fn apply_inner(&mut self, delta: TransactionDelta) -> Result<EffectRecord, StateError> {
        let effect = delta.effect;
        let accepted = effect.accepted.as_ref().ok_or(StateError::Integrity)?;
        if self.state.pool != accepted.before_pool {
            return Err(StateError::Integrity);
        }

        if self.state.spent.len() as u128 + accepted.nullifiers.len() as u128
            > u128::from(self.state.policy.limits().spent_markers())
            || self.state.leaves.len() as u128 + accepted.appends.len() as u128
                > u128::from(self.state.policy.limits().note_leaves())
        {
            return Err(StateError::Integrity);
        }

        for (i, n) in accepted.nullifiers.iter().enumerate() {
            if self.state.is_spent(*n) || accepted.nullifiers[..i].contains(n) {
                return Err(StateError::Integrity);
            }
        }

        let start = self.state.note_anchor().count().value();
        for (i, append) in accepted.appends.iter().enumerate() {
            if u128::from(append.position.value()) != start + i as u128 {
                return Err(StateError::Integrity);
            }
        }

        for (i, replacement) in accepted.accounts.iter().enumerate() {
            let account = self
                .state
                .account(replacement.account_id)
                .ok_or(StateError::Integrity)?;
            if account.balance() != replacement.before_balance
                || account.next_nonce() != replacement.before_nonce
                || (i > 0
                    && accepted.accounts[i - 1].account_id.as_bytes()
                        >= replacement.account_id.as_bytes())
            {
                return Err(StateError::Integrity);
            }
        }

        self.state
            .spent
            .try_reserve(accepted.nullifiers.len())
            .map_err(|_| StateError::Allocation)?;
        self.state
            .leaves
            .try_reserve(accepted.appends.len())
            .map_err(|_| StateError::Allocation)?;
        for (_index, n) in accepted.nullifiers.iter().enumerate() {
            self.state.spent.insert(n.into_bytes(), *n);
            #[cfg(all(test, feature = "experimental-profiles"))]
            if hit(FailurePoint::NullifierInsert(_index)) {
                return Err(StateError::Allocation);
            }
        }

        for (_index, append) in accepted.appends.iter().enumerate() {
            if self.append(append.commitment)? != append.position {
                return Err(StateError::Integrity);
            }

            #[cfg(all(test, feature = "experimental-profiles"))]
            if hit(FailurePoint::NoteAppend(_index)) {
                return Err(StateError::Allocation);
            }
        }

        for (_index, replacement) in accepted.accounts.iter().enumerate() {
            let current = self
                .state
                .accounts
                .get_mut(replacement.account_id.as_bytes())
                .ok_or(StateError::Integrity)?;
            *current = RewardAccount::new(
                current.withdrawal_authority().clone(),
                replacement.after_balance,
                replacement.after_nonce,
            );
            #[cfg(all(test, feature = "experimental-profiles"))]
            if hit(FailurePoint::AccountReplace(_index)) {
                return Err(StateError::Allocation);
            }
        }

        self.state.pool = accepted.after_pool;
        #[cfg(all(test, feature = "experimental-profiles"))]
        if hit(FailurePoint::PoolReplace) {
            return Err(StateError::Allocation);
        }

        self.validate_conservation()?;
        Ok(effect)
    }
}

/// Actual partial application failure checks.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use crate::execution::TransactionDelta;
    use crate::test_support::{FailurePoint, inject};
    use crate::test_support::{payment_body, trusted_manifest};
    use crate::{SnapshotRecord, WorkingState, encode_snapshot, validate_bootstrap};

    /// A failure after an append poisons only the disposable owner and never changes
    /// its parent.
    #[test]
    fn application_failure_aborts_instead_of_rejecting() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let old = encode_snapshot(&SnapshotRecord::from_state(parent.state()).unwrap()).unwrap();
        let mut working = WorkingState::reconstruct(parent.state()).unwrap();
        let (id, account) = parent.state().accounts().next().unwrap();
        let output = payment_body(2, 2).outputs().outputs()[0].commitment();
        let delta = TransactionDelta {
            effect: crate::EffectRecord {
                vertex_id: houseki_types::VertexId::from_bytes([1; 64]),
                transaction_index: 0,
                accepted: Some(crate::AcceptedEffect {
                    nullifiers: vec![],
                    appends: vec![
                        crate::NoteAppend {
                            position: houseki_types::NotePosition::new(1),
                            commitment: output,
                        },
                        crate::NoteAppend {
                            position: houseki_types::NotePosition::new(2),
                            commitment: output,
                        },
                    ],
                    accounts: vec![crate::AccountEffect {
                        account_id: houseki_types::RewardAccountId::from_bytes(*id),
                        before_balance: account.balance(),
                        before_nonce: account.next_nonce(),
                        after_balance: houseki_types::Amount::from_atoms(4).unwrap(),
                        after_nonce: account.next_nonce(),
                    }],
                    before_pool: parent.state().pool(),
                    after_pool: houseki_types::Amount::from_atoms(96).unwrap(),
                }),
            },
        };

        let _injection = inject(FailurePoint::NoteAppend(1));

        assert!(working.apply(delta).is_err());
        assert!(working.is_poisoned());
        assert_eq!(working.state().leaves().len(), 3);
        assert_eq!(
            encode_snapshot(&SnapshotRecord::from_state(parent.state()).unwrap()).unwrap(),
            old
        );
    }
}
