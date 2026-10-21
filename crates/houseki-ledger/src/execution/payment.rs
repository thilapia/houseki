//! Common rejection priority and complete payment delta preflight.

use super::{Decision, ExecutionError, TransactionDelta, context};
use crate::eligibility::AuthorizedOccurrence;
use crate::{
    AcceptedEffect, AccountEffect, CheckpointRules, EffectRecord, NoteAppend, WorkingState,
};
use houseki_types::{ExecutionRejectionReason as R, NotePosition, TransactionEnvelope};

/// Evaluates an authorized payment in explicit rejection priority without writing state.
pub(super) fn evaluate_payment(
    rules: &CheckpointRules,
    working: &WorkingState,
    occurrence: &AuthorizedOccurrence<'_>,
) -> Result<Decision, ExecutionError> {
    if let Some(reason) = context::check(rules, working, occurrence)? {
        return Ok(Decision::Reject(reason));
    }

    let TransactionEnvelope::Payment(envelope) = occurrence.occurrence().envelope() else {
        return Err(ExecutionError::Integrity);
    };
    let body = envelope.body();
    let state = working.state();
    let policy = rules.policy();
    let anchor = occurrence.anchor().ok_or(ExecutionError::Integrity)?;
    if !rules.allows_anchor(anchor) {
        return Ok(Decision::Reject(R::DisallowedAnchor));
    }

    if body.context().fee_schedule_id() != policy.fee_schedule() {
        return Ok(Decision::Reject(R::WrongFeeSchedule));
    }

    let fee = policy.payment_fee(body)?;
    if body.public_fee() != fee {
        return Ok(Decision::Reject(R::WrongFee));
    }

    if body
        .inputs()
        .nullifiers()
        .iter()
        .any(|n| state.is_spent(*n))
    {
        return Ok(Decision::Reject(R::SpentNullifier));
    }

    let beneficiary = state
        .beneficiary(occurrence.occurrence().vertex_author())
        .ok_or(ExecutionError::Integrity)?;
    let account = state
        .account(beneficiary)
        .ok_or(ExecutionError::Integrity)?;
    let after_balance = account.balance().checked_add(fee);
    let after_pool = state.pool().checked_sub(fee);
    let enough_notes = (state.leaves().len() as u128) + (body.outputs().output_count() as u128)
        <= u128::from(policy.limits().note_leaves());
    let enough_spent = (state.spent.len() as u128) + (body.inputs().input_count() as u128)
        <= u128::from(policy.limits().spent_markers());
    if !enough_notes || !enough_spent || after_balance.is_err() || after_pool.is_err() {
        return Ok(Decision::Reject(R::StateBoundsExceeded));
    }

    let start = u64::try_from(state.note_anchor().count().value())
        .map_err(|_| ExecutionError::Integrity)?;
    let appends = body
        .outputs()
        .outputs()
        .iter()
        .enumerate()
        .map(|(slot, output)| NoteAppend {
            position: NotePosition::new(start + slot as u64),
            commitment: output.commitment(),
        })
        .collect();

    Ok(Decision::Accept(TransactionDelta {
        effect: EffectRecord {
            vertex_id: occurrence.occurrence().vertex_id(),
            transaction_index: occurrence.occurrence().transaction_index(),
            accepted: Some(AcceptedEffect {
                nullifiers: body.inputs().nullifiers().to_vec(),
                appends,
                accounts: vec![AccountEffect {
                    account_id: beneficiary,
                    before_balance: account.balance(),
                    before_nonce: account.next_nonce(),
                    after_balance: after_balance.map_err(|_| ExecutionError::Integrity)?,
                    after_nonce: account.next_nonce(),
                }],
                before_pool: state.pool(),
                after_pool: after_pool.map_err(|_| ExecutionError::Integrity)?,
            }),
        },
    }))
}

/// Payment delta and rejection precedence tests use private synthetic eligibility only.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::eligibility::AuthorizedOccurrence;
    use crate::test_support::{payment_body, trusted_manifest};
    use crate::{CheckpointRules, WorkingState, validate_bootstrap};
    use houseki_proofs::ProofContext;
    use houseki_types::{
        Amount, CheckpointSequence, EncodedTransactionProof, Occurrence, PaymentBody,
        PaymentCountLimits, PaymentEnvelope, TransactionContext, ValidatorId, VertexId,
    };

    /// Creates an exact policy shaped payment against the actual trusted initial
    /// anchor.
    fn fixture() -> (crate::ParentSnapshot, Occurrence) {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let base = payment_body(2, 2);
        let c = base.context();
        let context = TransactionContext::new(
            parent.state().network(),
            c.protocol_version(),
            c.proof_profile_id(),
            c.fee_schedule_id(),
            c.validity_checkpoint_range(),
        );
        let inputs = houseki_types::PaymentInputs::new(
            parent.state().note_anchor().root(),
            base.inputs().nullifiers().to_vec(),
            PaymentCountLimits::new(4, 2).unwrap(),
        )
        .unwrap();
        let body = PaymentBody::new(
            context,
            inputs,
            base.outputs().clone(),
            Amount::from_atoms(4).unwrap(),
            PaymentCountLimits::new(4, 2).unwrap(),
        )
        .unwrap();
        let occurrence = Occurrence::new(
            VertexId::from_bytes([1; 64]),
            ValidatorId::from_bytes([5; 64]),
            parent.state().committee_context(),
            0,
            PaymentEnvelope::new(body, EncodedTransactionProof::new(vec![], 0).unwrap()).into(),
        );
        (parent, occurrence)
    }

    /// Computes conserved public fee effects while preserving ordered nullifiers and
    /// repeated outputs.
    #[test]
    fn payment_delta_conserves_fee_and_order() {
        let (parent, occurrence) = fixture();
        let context = match occurrence.envelope() {
            houseki_types::TransactionEnvelope::Payment(e) => {
                ProofContext::new(e.body().context()).unwrap()
            }
            _ => unreachable!(),
        };

        let checked = AuthorizedOccurrence::for_test(
            &occurrence,
            &context,
            Some(parent.state().note_anchor()),
        );

        let working = WorkingState::reconstruct(parent.state()).unwrap();
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();

        let Decision::Accept(delta) = evaluate_payment(&rules, &working, &checked).unwrap() else {
            panic!("payment should accept")
        };
        let effect = delta.effect.accepted.unwrap();

        assert_eq!(
            (effect.before_pool.atoms(), effect.after_pool.atoms()),
            (100, 96)
        );
        assert_eq!(
            (
                effect.accounts[0].before_balance.atoms(),
                effect.accounts[0].after_balance.atoms()
            ),
            (0, 4)
        );
        assert_eq!(effect.nullifiers.len(), 2);
        assert_eq!(
            effect
                .appends
                .iter()
                .map(|a| a.position.value())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(effect.appends[0].commitment, effect.appends[1].commitment);
        assert_eq!(working.state().pool().atoms(), 100);
    }

    /// A spent marker rejects the occurrence before any delta or fee can be applied.
    #[test]
    fn spent_payment_has_empty_effect() {
        let (parent, occurrence) = fixture();
        let houseki_types::TransactionEnvelope::Payment(e) = occurrence.envelope() else {
            unreachable!()
        };
        let context = ProofContext::new(e.body().context()).unwrap();
        let checked = AuthorizedOccurrence::for_test(
            &occurrence,
            &context,
            Some(parent.state().note_anchor()),
        );

        let mut working = WorkingState::reconstruct(parent.state()).unwrap();
        let n = e.body().inputs().nullifiers()[0];
        working.state.spent.insert(n.into_bytes(), n);
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(0)).unwrap();

        assert!(matches!(
            evaluate_payment(&rules, &working, &checked).unwrap(),
            Decision::Reject(houseki_types::ExecutionRejectionReason::SpentNullifier)
        ));
        assert_eq!(working.state().pool().atoms(), 100);
    }

    /// Earlier context and validity failures win over all later fee and spent failures.
    #[test]
    fn payment_rejection_priority_is_explicit() {
        let (parent, occurrence) = fixture();
        let houseki_types::TransactionEnvelope::Payment(e) = occurrence.envelope() else {
            unreachable!()
        };
        let context = ProofContext::new(e.body().context()).unwrap();
        let checked = AuthorizedOccurrence::for_test(
            &occurrence,
            &context,
            Some(parent.state().note_anchor()),
        );

        let mut working = WorkingState::reconstruct(parent.state()).unwrap();
        let n = e.body().inputs().nullifiers()[0];
        working.state.spent.insert(n.into_bytes(), n);
        let rules = CheckpointRules::derive(parent.state(), CheckpointSequence::new(10)).unwrap();

        assert!(matches!(
            evaluate_payment(&rules, &working, &checked).unwrap(),
            Decision::Reject(houseki_types::ExecutionRejectionReason::OutsideValidityRange)
        ));
    }

    /// Every simultaneous failure selects the first applicable reason in the explicit
    /// table.
    #[test]
    fn complete_payment_priority_table() {
        use houseki_types::{
            ExecutionRejectionReason as R, FeeScheduleId, NetworkId, ValidityCheckpointRange,
        };
        let expected = [
            R::UnsupportedContext,
            R::OutsideValidityRange,
            R::DisallowedAnchor,
            R::WrongFeeSchedule,
            R::WrongFee,
            R::SpentNullifier,
            R::StateBoundsExceeded,
        ];

        for (priority, reason) in expected.into_iter().enumerate() {
            let (parent, original) = fixture();

            let mut working = WorkingState::reconstruct(parent.state()).unwrap();
            std::sync::Arc::make_mut(&mut working.state.policy)
                .limits
                .note_leaves = 0;
            if priority > 2 {
                working.state.anchors.push(crate::AnchorRecord::new(
                    CheckpointSequence::new(32),
                    parent.state().note_anchor(),
                ));
            }

            let houseki_types::TransactionEnvelope::Payment(e) = original.envelope() else {
                unreachable!()
            };
            let c = e.body().context();
            let validity = ValidityCheckpointRange::new(
                CheckpointSequence::new(if priority <= 1 { 50 } else { 0 }),
                CheckpointSequence::new(100),
            )
            .unwrap();

            let context = TransactionContext::new(
                if priority == 0 {
                    NetworkId::from_bytes([8; 64])
                } else {
                    parent.state().network()
                },
                c.protocol_version(),
                c.proof_profile_id(),
                if priority <= 3 {
                    FeeScheduleId::new(0)
                } else {
                    c.fee_schedule_id()
                },
                validity,
            );

            let body = PaymentBody::new(
                context,
                e.body().inputs().clone(),
                e.body().outputs().clone(),
                Amount::from_atoms(if priority <= 4 { 0 } else { 4 }).unwrap(),
                PaymentCountLimits::new(4, 2).unwrap(),
            )
            .unwrap();

            if priority <= 5 {
                let n = body.inputs().nullifiers()[0];
                working.state.spent.insert(n.into_bytes(), n);
            }

            let occurrence = Occurrence::new(
                original.vertex_id(),
                original.vertex_author(),
                original.committee_context(),
                0,
                PaymentEnvelope::new(body, EncodedTransactionProof::new(vec![], 0).unwrap()).into(),
            );
            let context = ProofContext::new(context).unwrap();
            let checked = AuthorizedOccurrence::for_test(
                &occurrence,
                &context,
                Some(parent.state().note_anchor()),
            );
            let rules =
                CheckpointRules::derive(working.state(), CheckpointSequence::new(32)).unwrap();

            assert!(matches!(
                evaluate_payment(&rules, &working, &checked).unwrap(),
                Decision::Reject(actual) if actual == reason
            ));
        }
    }
}
