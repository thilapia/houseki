//! A state decision evaluated under fixed checkpoint rules.

use super::TransactionDelta;
use houseki_types::ExecutionRejectionReason;

/// One state decision after complete unit eligibility has succeeded.
pub(crate) enum Decision {
    /// Complete preflighted accepted effects with no writes yet applied.
    Accept(
        /// Complete checked effects to apply if this occurrence is accepted.
        TransactionDelta,
    ),

    /// One explicit canonical reason with no effects.
    Reject(
        /// Canonical rejection reason with no accompanying state effects.
        ExecutionRejectionReason,
    ),
}
