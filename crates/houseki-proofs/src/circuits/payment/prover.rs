//! Complete payment proving from borrowed original owners.

use super::{PaymentAir, PaymentLayout, trace};
use crate::{
    CancellationToken, PaymentWitness, ProofContext, ProofRuntime, ProveError, StatementError,
    backend, cancellation::Attempt, context::require_context,
    profile::payment::SupportedPaymentShape, statement::Statement,
};
use houseki_types::{EncodedTransactionProof, NoteTreeAnchor, PaymentBody};

/// Proves authority, occupied membership, nullifiers, outputs and exact conservation for one payment.
///
/// The application installs [`crate::ProofAllocator`] and uses serial backend execution with
/// panic unwinding enabled so private allocations are cleared on normal exit and unwinding.
///
/// Original openings, keys and paths remain borrowed for this call and no private state is cached.
///
/// Fee policy, unspentness, anchor eligibility, encrypted delivery and atomic execution remain
/// obligations of the consumer before applying the transaction.
///
/// # Errors
///
/// Checks runtime admission before consuming the cancellation token, then exact context, supported
/// counts, family identity and witness counts before encoding the statement or importing secrets.
///
/// Native witness validation precedes protected preparation and fresh backend entropy.
///
/// Every admitted call consumes its token even on failure and returns only a complete proof.
pub fn prove_payment(
    runtime: &ProofRuntime,
    body: &PaymentBody,
    anchor: &NoteTreeAnchor,
    witness: &PaymentWitness<'_>,
    context: &ProofContext,
    cancellation: &CancellationToken,
) -> Result<EncodedTransactionProof, ProveError> {
    let admission = runtime.acquire().map_err(|_| ProveError::Busy)?;
    let attempt = Attempt::new(cancellation).ok_or(ProveError::Cancelled)?;
    require_context(context.expected(), body.context())
        .map_err(|_| StatementError::ContextMismatch)?;
    let shape =
        SupportedPaymentShape::new(body.inputs().input_count(), body.outputs().output_count())
            .map_err(|_| StatementError::UnsupportedShape)?;
    let identity = context.payment_identity(shape)?;
    if witness.inputs().len() != shape.inputs() || witness.outputs().len() != shape.outputs() {
        return Err(ProveError::WitnessCountMismatch);
    }

    let statement = Statement::payment(
        body,
        anchor,
        context.expected(),
        &identity,
        context.body_limits(),
    )?;
    houseki_notes::check_payment(
        body,
        anchor,
        witness.inputs(),
        witness.outputs(),
        context.body_limits().payment_counts(),
    )
    .map_err(|_| ProveError::InvalidWitness)?;
    let layout = PaymentLayout::for_shape(shape).map_err(|_| ProveError::BackendUnavailable)?;
    let air = PaymentAir::new(&layout);
    backend::prove_payment(
        &admission,
        &statement,
        &identity,
        &air,
        || trace::build(&air, witness, &statement, cancellation),
        attempt,
    )
    .map_err(ProveError::from)
}

