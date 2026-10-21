//! Synthetic occurrence construction for private transition model tests only.

use super::payment_body;
use crate::LogicalState;
use houseki_types::{
    Amount, EncodedTransactionProof, Occurrence, PaymentBody, PaymentCountLimits, PaymentEnvelope,
    PaymentInputs, TransactionContext, ValidatorId, VertexId,
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
