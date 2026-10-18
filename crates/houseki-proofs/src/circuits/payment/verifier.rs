//! Independent payment verification against the caller's exact public statement.

use super::{PaymentAir, PaymentLayout, VerifiedPayment};
use crate::{
    ProofContext, ProofRuntime, StatementError, VerifyError, backend, context::require_context,
    profile::payment::SupportedPaymentShape, statement::Statement,
};
use houseki_types::{EncodedTransactionProof, NoteTreeAnchor, PaymentBody};

/// Verifies the complete payment relation without private owners or proving entropy.
///
/// The expected context and anchor must be selected independently of supplied proof metadata.
///
/// The consumer still checks fees, unspentness, anchor eligibility, activation, tree capacity and
/// encrypted delivery before applying all effects atomically.
///
/// # Errors
///
/// Checks runtime admission, exact context, supported counts and family identity before bounded
/// statement construction, canonical proof decoding and cryptographic verification.
pub fn verify_payment<'a>(
    runtime: &ProofRuntime,
    body: &'a PaymentBody,
    anchor: &'a NoteTreeAnchor,
    proof: &EncodedTransactionProof,
    context: &'a ProofContext,
) -> Result<VerifiedPayment<'a>, VerifyError> {
    let admission = runtime.acquire().map_err(|_| VerifyError::Busy)?;
    require_context(context.expected(), body.context())
        .map_err(|_| StatementError::ContextMismatch)?;
    let shape =
        SupportedPaymentShape::new(body.inputs().input_count(), body.outputs().output_count())
            .map_err(|_| StatementError::UnsupportedShape)?;
    let identity = context.payment_identity(shape)?;
    let statement = Statement::payment(
        body,
        anchor,
        context.expected(),
        &identity,
        context.body_limits(),
    )?;
    let layout = PaymentLayout::for_shape(shape).map_err(|_| VerifyError::BackendUnavailable)?;
    let air = PaymentAir::new(&layout);
    backend::verify_payment(&admission, &statement, &identity, &air, proof)?;

    Ok(VerifiedPayment {
        body,
        anchor,
        context,
    })
}
