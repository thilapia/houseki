//! Complete preflighted public transaction delta without a public application constructor.

use crate::EffectRecord;
use houseki_types::ExecutionRejectionReason;

/// A complete accepted transition built only by the ordered evaluator.
pub(crate) struct TransactionDelta {
    /// Origin, ordered markers/appends and coalesced before/after account and pool values.
    pub(crate) effect: EffectRecord,
}

/// One state decision after complete unit eligibility has succeeded.
pub(crate) enum Decision {
    /// Complete preflighted accepted effects with no writes yet applied.
    Accept(TransactionDelta),

    /// One explicit canonical reason with no effects.
    Reject(ExecutionRejectionReason),
}
