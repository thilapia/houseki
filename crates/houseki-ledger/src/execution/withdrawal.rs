//! Checked gross withdrawal affordability, nonce advancement and account aliasing.

use super::{Decision, ExecutionError, TransactionDelta, common};
use crate::eligibility::AuthorizedOccurrence;
use crate::{
    AcceptedEffect, AccountEffect, CheckpointRules, EffectRecord, NoteAppend, WorkingState,
};
use houseki_types::{Amount, ExecutionRejectionReason as R, NotePosition, TransactionEnvelope};

/// Builds a complete coalesced withdrawal delta after explicit nonce and gross-funds precedence.
pub(super) fn evaluate_withdrawal(
    rules: &CheckpointRules,
    working: &WorkingState,
    occurrence: &AuthorizedOccurrence<'_>,
) -> Result<Decision, ExecutionError> {
    if let Some(reason) = common::check(rules, working, occurrence)? {
        return Ok(Decision::Reject(reason));
    }
    let TransactionEnvelope::RewardWithdrawal(envelope) = occurrence.occurrence().envelope() else {
        return Err(ExecutionError::Integrity);
    };
    let body = envelope.body();
    let state = working.state();
    let policy = rules.policy();
    if body.context().fee_schedule_id() != policy.fee_schedule() {
        return Ok(Decision::Reject(R::WrongFeeSchedule));
    }
    let fee = policy.withdrawal_fee();
    if body.public_fee() != fee {
        return Ok(Decision::Reject(R::WrongFee));
    }
    let source = state
        .account(body.reward_account_id())
        .ok_or(ExecutionError::Integrity)?;
    if body.nonce() != source.next_nonce() {
        return Ok(Decision::Reject(R::WrongNonce));
    }
    let Some(next_nonce) = source.next_nonce().checked_next() else {
        return Ok(Decision::Reject(R::NonceExhausted));
    };
    let gross = body
        .public_amount()
        .atoms()
        .checked_add(fee.atoms())
        .ok_or(ExecutionError::Integrity)?;
    if source.balance().atoms() < gross {
        return Ok(Decision::Reject(R::InsufficientBalance));
    }
    let beneficiary = state
        .beneficiary(occurrence.occurrence().vertex_author())
        .ok_or(ExecutionError::Integrity)?;
    let recipient = state
        .account(beneficiary)
        .ok_or(ExecutionError::Integrity)?;
    let after_pool = state.pool().checked_add(body.public_amount());
    let enough_notes = (state.leaves().len() as u128) < u128::from(policy.limits().note_leaves());
    let recipient_balance = if beneficiary == body.reward_account_id() {
        source.balance().checked_sub(body.public_amount())
    } else {
        recipient.balance().checked_add(fee)
    };
    if after_pool.is_err() || recipient_balance.is_err() || !enough_notes {
        return Ok(Decision::Reject(R::StateBoundsExceeded));
    }
    let mut accounts = if beneficiary == body.reward_account_id() {
        vec![AccountEffect {
            account_id: beneficiary,
            before_balance: source.balance(),
            before_nonce: source.next_nonce(),
            after_balance: recipient_balance.map_err(|_| ExecutionError::Integrity)?,
            after_nonce: next_nonce,
        }]
    } else {
        vec![
            AccountEffect {
                account_id: body.reward_account_id(),
                before_balance: source.balance(),
                before_nonce: source.next_nonce(),
                after_balance: Amount::from_atoms(source.balance().atoms() - gross)
                    .map_err(|_| ExecutionError::Integrity)?,
                after_nonce: next_nonce,
            },
            AccountEffect {
                account_id: beneficiary,
                before_balance: recipient.balance(),
                before_nonce: recipient.next_nonce(),
                after_balance: recipient_balance.map_err(|_| ExecutionError::Integrity)?,
                after_nonce: recipient.next_nonce(),
            },
        ]
    };
    accounts.sort_unstable_by_key(|a| a.account_id.into_bytes());
    let position = NotePosition::new(
        u64::try_from(state.note_anchor().count().value())
            .map_err(|_| ExecutionError::Integrity)?,
    );
    Ok(Decision::Accept(TransactionDelta {
        effect: EffectRecord {
            vertex_id: occurrence.occurrence().vertex_id(),
            transaction_index: occurrence.occurrence().transaction_index(),
            accepted: Some(AcceptedEffect {
                nullifiers: vec![],
                appends: vec![NoteAppend {
                    position,
                    commitment: body.output().commitment(),
                }],
                accounts,
                before_pool: state.pool(),
                after_pool: after_pool.map_err(|_| ExecutionError::Integrity)?,
            }),
        },
    }))
}

/// Withdrawal preflight tests use private synthetic eligibility only.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::eligibility::AuthorizedOccurrence;
    use crate::test_support::{payment_body, trusted_manifest};
    use crate::{CheckpointRules, WorkingState, validate_bootstrap};
    use houseki_proofs::ProofContext;
    use houseki_types::{
        Amount, CheckpointSequence, EncodedTransactionProof, Occurrence, ProofProfileId,
        RewardAccount, RewardWithdrawalBody, RewardWithdrawalEnvelope, TransactionContext,
        ValidatorId, VertexId, WithdrawalNonce,
    };

    /// Builds a synthetic withdrawal under the actual registered authority and active policy.
    fn fixture(
        balance: u128,
        stored_nonce: u64,
        body_nonce: u64,
    ) -> (crate::ParentSnapshot, WorkingState, Occurrence) {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let mut working = WorkingState::reconstruct(parent.state()).unwrap();
        let (id, account) = parent.state().accounts().next().unwrap();
        let account_id = houseki_types::RewardAccountId::from_bytes(*id);
        working.state.accounts.insert(
            *id,
            RewardAccount::new(
                account.withdrawal_authority().clone(),
                Amount::from_atoms(balance).unwrap(),
                WithdrawalNonce::new(stored_nonce),
            ),
        );
        working.state.pool = Amount::from_atoms(100 - balance).unwrap();
        let payment = payment_body(1, 1);
        let c = payment.context();
        let context = TransactionContext::new(
            parent.state().network(),
            c.protocol_version(),
            ProofProfileId::new(0xffff0007),
            c.fee_schedule_id(),
            c.validity_checkpoint_range(),
        );
        let body = RewardWithdrawalBody::new(
            context,
            account_id,
            account.withdrawal_authority().clone(),
            WithdrawalNonce::new(body_nonce),
            Amount::from_atoms(3).unwrap(),
            Amount::from_atoms(1).unwrap(),
            payment.outputs().outputs()[0].clone(),
        )
        .unwrap();
        let occurrence = Occurrence::new(
            VertexId::from_bytes([1; 64]),
            ValidatorId::from_bytes([5; 64]),
            parent.state().committee_context(),
            0,
            RewardWithdrawalEnvelope::new(
                body,
                EncodedTransactionProof::new(vec![], 0).unwrap(),
                houseki_types::EncodedMlDsa87Signature::from_bytes([0; 4627]),
            )
            .into(),
        );
        (parent, working, occurrence)
    }

    /// Gross affordability is required even when the source also receives this occurrence's fee.
    #[test]
    fn withdrawal_requires_gross_balance_before_fee_credit() {
        let (parent, working, occurrence) = fixture(3, 0, 0);
        let houseki_types::TransactionEnvelope::RewardWithdrawal(e) = occurrence.envelope() else {
            unreachable!()
        };
        let context = ProofContext::new(e.body().context()).unwrap();
        let checked = AuthorizedOccurrence::for_test(&occurrence, &context, None);
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();
        assert!(matches!(
            evaluate_withdrawal(&rules, &working, &checked).unwrap(),
            Decision::Reject(R::InsufficientBalance)
        ));
        assert_eq!(
            working
                .state()
                .account(e.body().reward_account_id())
                .unwrap()
                .balance()
                .atoms(),
            3
        );
    }

    /// Nonce mismatch wins over exhaustion, which in turn wins over insufficient funds.
    #[test]
    fn withdrawal_nonce_and_balance_priority() {
        for (body_nonce, expected) in [(0, R::WrongNonce), (u64::MAX, R::NonceExhausted)] {
            let (parent, working, occurrence) = fixture(0, u64::MAX, body_nonce);
            let houseki_types::TransactionEnvelope::RewardWithdrawal(e) = occurrence.envelope()
            else {
                unreachable!()
            };
            let context = ProofContext::new(e.body().context()).unwrap();
            let checked = AuthorizedOccurrence::for_test(&occurrence, &context, None);
            let rules =
                CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();
            assert!(
                matches!(evaluate_withdrawal(&rules,&working,&checked).unwrap(),Decision::Reject(reason)if reason==expected)
            );
        }
    }

    /// Source and beneficiary alias produces one merged replacement with one nonce advancement.
    #[test]
    fn withdrawal_coalesces_aliasing() {
        let (parent, working, occurrence) = fixture(4, 0, 0);
        let houseki_types::TransactionEnvelope::RewardWithdrawal(e) = occurrence.envelope() else {
            unreachable!()
        };
        let context = ProofContext::new(e.body().context()).unwrap();
        let checked = AuthorizedOccurrence::for_test(&occurrence, &context, None);
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();
        let Decision::Accept(delta) = evaluate_withdrawal(&rules, &working, &checked).unwrap()
        else {
            panic!("withdrawal should accept")
        };
        let effect = delta.effect.accepted.unwrap();
        assert_eq!(effect.accounts.len(), 1);
        assert_eq!(effect.accounts[0].after_balance.atoms(), 1);
        assert_eq!(effect.accounts[0].after_nonce.value(), 1);
        assert_eq!(
            (effect.before_pool.atoms(), effect.after_pool.atoms()),
            (96, 99)
        );
    }
    /// A non-validator source remains withdrawable through a distinct mapped fee beneficiary.
    #[test]
    fn distinct_accounts_preserve_gross_debit_and_fee() {
        let (parent, mut working, occurrence) = fixture(4, 0, 0);
        let key = houseki_types::EncodedMlDsa87PublicKey::from_bytes([15; 2592]);
        let id = houseki_crypto::MlDsa87VerificationKey::from_encoded(&key)
            .reward_account_id(parent.state().network())
            .unwrap();
        working.state.accounts.insert(
            id.into_bytes(),
            RewardAccount::new(key, Amount::from_atoms(0).unwrap(), WithdrawalNonce::new(0)),
        );
        std::sync::Arc::make_mut(&mut working.state.committee).insert(
            ValidatorId::from_bytes([5; 64]).into_bytes(),
            crate::CommitteeEntry::new(ValidatorId::from_bytes([5; 64]), 1, id, vec![]),
        );
        let houseki_types::TransactionEnvelope::RewardWithdrawal(e) = occurrence.envelope() else {
            unreachable!()
        };
        let context = ProofContext::new(e.body().context()).unwrap();
        let checked = AuthorizedOccurrence::for_test(&occurrence, &context, None);
        let rules = CheckpointRules::derive(working.state(), CheckpointSequence::new(0)).unwrap();
        let Decision::Accept(delta) = evaluate_withdrawal(&rules, &working, &checked).unwrap()
        else {
            panic!("withdrawal should accept")
        };
        let effect = delta.effect.accepted.unwrap();
        assert_eq!(effect.accounts.len(), 2);
        assert_eq!(
            effect
                .accounts
                .iter()
                .find(|a| a.account_id == e.body().reward_account_id())
                .unwrap()
                .after_balance
                .atoms(),
            0
        );
        assert_eq!(
            effect
                .accounts
                .iter()
                .find(|a| a.account_id == id)
                .unwrap()
                .after_balance
                .atoms(),
            1
        );
    }

    /// Gross affordability compares a full-width amount-plus-fee before capped amount conversion.
    #[test]
    fn maximum_amount_plus_fee_is_insufficient_balance() {
        let (parent, mut working, original) = fixture(4, 0, 0);
        let houseki_types::TransactionEnvelope::RewardWithdrawal(e) = original.envelope() else {
            unreachable!()
        };
        let b = e.body();
        let maximum = Amount::from_atoms(Amount::MAX_ATOMS).unwrap();
        working.state.accounts.insert(
            b.reward_account_id().into_bytes(),
            RewardAccount::new(
                b.withdrawal_public_key().clone(),
                maximum,
                WithdrawalNonce::new(0),
            ),
        );
        working.state.pool = Amount::from_atoms(0).unwrap();
        working.state.issued = maximum;
        let body = RewardWithdrawalBody::new(
            b.context(),
            b.reward_account_id(),
            b.withdrawal_public_key().clone(),
            b.nonce(),
            maximum,
            b.public_fee(),
            b.output().clone(),
        )
        .unwrap();
        let context = ProofContext::new(body.context()).unwrap();
        let occurrence = Occurrence::new(
            original.vertex_id(),
            original.vertex_author(),
            original.committee_context(),
            0,
            RewardWithdrawalEnvelope::new(body, e.proof().clone(), e.signature().clone()).into(),
        );
        let checked = AuthorizedOccurrence::for_test(&occurrence, &context, None);
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();
        assert!(matches!(
            evaluate_withdrawal(&rules, &working, &checked).unwrap(),
            Decision::Reject(R::InsufficientBalance)
        ));
    }
    /// A separately identified zero-fee test schedule retains exact gross arithmetic and conservation.
    #[test]
    fn zero_fee_requires_a_distinct_schedule() {
        let (parent, mut working, original) = fixture(3, 0, 0);
        let houseki_types::TransactionEnvelope::RewardWithdrawal(e) = original.envelope() else {
            unreachable!()
        };
        let b = e.body();
        let policy = std::sync::Arc::make_mut(&mut working.state.policy);
        policy.fee_schedule = houseki_types::FeeScheduleId::new(0xffff0002);
        policy.withdrawal_fee = Amount::from_atoms(0).unwrap();
        policy.validate().unwrap();
        let c = b.context();
        let context = TransactionContext::new(
            c.network_id(),
            c.protocol_version(),
            c.proof_profile_id(),
            working.state.policy.fee_schedule(),
            c.validity_checkpoint_range(),
        );
        let body = RewardWithdrawalBody::new(
            context,
            b.reward_account_id(),
            b.withdrawal_public_key().clone(),
            b.nonce(),
            b.public_amount(),
            Amount::from_atoms(0).unwrap(),
            b.output().clone(),
        )
        .unwrap();
        let occurrence = Occurrence::new(
            original.vertex_id(),
            original.vertex_author(),
            original.committee_context(),
            0,
            RewardWithdrawalEnvelope::new(body, e.proof().clone(), e.signature().clone()).into(),
        );
        let context = ProofContext::new(context).unwrap();
        let checked = AuthorizedOccurrence::for_test(&occurrence, &context, None);
        let rules = CheckpointRules::derive(working.state(), CheckpointSequence::new(0)).unwrap();
        let Decision::Accept(delta) = evaluate_withdrawal(&rules, &working, &checked).unwrap()
        else {
            panic!("zero-fee transfer should accept")
        };
        working.apply(delta).unwrap();
        assert_eq!(working.state().pool().atoms(), 100);
        assert_eq!(
            working
                .state()
                .account(b.reward_account_id())
                .unwrap()
                .balance()
                .atoms(),
            0
        );
        assert_eq!(parent.state().pool().atoms(), 100);
    }
}
