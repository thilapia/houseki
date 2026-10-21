//! Synthetic occurrence construction for private transition-model tests only.

use super::payment_body;
use crate::LogicalState;
use houseki_types::{
    Amount, EncodedMlDsa87Signature, EncodedTransactionProof, FeeScheduleId, Occurrence,
    PaymentBody, PaymentCountLimits, PaymentEnvelope, PaymentInputs, ProofProfileId,
    RewardAccountId, RewardWithdrawalBody, RewardWithdrawalEnvelope, TransactionContext,
    ValidatorId, VertexId, WithdrawalNonce,
};

/// Constructs an understood payment with distinct marker bytes and exact shape fees.
pub(crate) fn payment(
    state: &LogicalState,
    index: u64,
    marker: u8,
    author: ValidatorId,
) -> Occurrence {
    let base = payment_body(2, 2);
    let c = base.context();
    let context = TransactionContext::new(
        state.network(),
        c.protocol_version(),
        c.proof_profile_id(),
        state.policy().fee_schedule(),
        c.validity_checkpoint_range(),
    );
    let inputs = PaymentInputs::new(
        state.note_anchor().root(),
        vec![
            houseki_types::Nullifier::from_bytes([marker; 64]),
            houseki_types::Nullifier::from_bytes([marker.wrapping_add(1); 64]),
        ],
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
    Occurrence::new(
        VertexId::from_bytes([1; 64]),
        author,
        state.committee_context(),
        index,
        PaymentEnvelope::new(body, EncodedTransactionProof::new(vec![], 0).unwrap()).into(),
    )
}

/// Constructs an understood withdrawal without creating any public authorization bypass.
pub(crate) fn withdrawal(
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
