//! Explicit common state-check precedence independent of enum discriminants.

use super::ExecutionError;
use crate::eligibility::AuthorizedOccurrence;
use crate::{CheckpointRules, WorkingState};
use houseki_types::{ExecutionRejectionReason as R, TransactionContext, TransactionEnvelope};

/// Resolves the exact body context without trusting unrelated caller fields.
pub(super) fn body_context(occurrence: &AuthorizedOccurrence<'_>) -> TransactionContext {
    match occurrence.occurrence().envelope() {
        TransactionEnvelope::Payment(e) => e.body().context(),
        TransactionEnvelope::RewardWithdrawal(e) => e.body().context(),
    }
}

/// Checks immutable evidence agreement, then activation and the inclusive validity window.
pub(super) fn check(
    rules: &CheckpointRules,
    working: &WorkingState,
    occurrence: &AuthorizedOccurrence<'_>,
) -> Result<Option<R>, ExecutionError> {
    let context = body_context(occurrence);
    if occurrence.context().expected() != context {
        return Err(ExecutionError::Integrity);
    }
    if context.network_id() != working.state().network()
        || !rules
            .policy()
            .activates(occurrence.occurrence().envelope().kind(), context)
    {
        return Ok(Some(R::UnsupportedContext));
    }
    if !context
        .validity_checkpoint_range()
        .contains(rules.sequence())
    {
        return Ok(Some(R::OutsideValidityRange));
    }
    Ok(None)
}
