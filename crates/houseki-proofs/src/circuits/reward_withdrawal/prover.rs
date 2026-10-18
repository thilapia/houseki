//! Withdrawal proving from a borrowed native owner inside the shared protected backend.

use super::{WithdrawalAir, trace};
use crate::{
    CancellationToken, ProofContext, ProofRuntime, ProveError, backend, cancellation::Attempt,
    statement::Statement,
};
use houseki_notes::{NoteOpening, check_withdrawal_output};
use houseki_types::{EncodedTransactionProof, RewardWithdrawalBody};

/// Proves one ordinary output containing exactly the body's positive public withdrawal amount.
///
/// The application installs [`crate::ProofAllocator`] and uses serial backend execution with
/// panic unwinding enabled so private allocations are cleared on normal exit and unwinding.
///
/// The opening remains borrowed for this call and no witness or proving state is cached.
///
/// This output proof does not authorize the source account or establish encrypted delivery.
///
/// # Errors
///
/// Checks admission before consuming the cancellation token, exact context, bounded body encoding
/// and native witness validity, followed by protected backend preparation and fresh entropy.
///
/// Every admitted call consumes its token even when validation fails, and an interrupted attempt
/// returns no proof bytes and must be retried with a fresh token.
pub fn prove_reward_withdrawal(
    runtime: &ProofRuntime,
    body: &RewardWithdrawalBody,
    opening: &NoteOpening,
    context: &ProofContext,
    cancellation: &CancellationToken,
) -> Result<EncodedTransactionProof, ProveError> {
    let admission = runtime.acquire().map_err(|_| ProveError::Busy)?;
    let attempt = Attempt::new(cancellation).ok_or(ProveError::Cancelled)?;
    let statement =
        Statement::withdrawal(body, context.expected(), context.withdrawal_identity()?)?;
    check_withdrawal_output(body, opening).map_err(|_| ProveError::InvalidWitness)?;

    let air = WithdrawalAir::new();
    backend::prove_withdrawal(
        &admission,
        &statement,
        context.withdrawal_identity()?,
        &air,
        || trace::build(&air, opening, cancellation),
        attempt,
    )
    .map_err(ProveError::from)
}
