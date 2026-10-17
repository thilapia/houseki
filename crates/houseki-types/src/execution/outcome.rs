//! State outcomes for eligible transaction occurrences.

use super::ExecutionRejectionReason;

/// The reported state outcome of an eligible transaction occurrence.
///
/// Execution evaluates each occurrence against the state at its position in the canonical order.
///
/// This outcome belongs to that occurrence, so a rejected copy does not determine the outcome of
/// another occurrence of the same transaction.
///
/// Malformed payloads, invalid proofs and invalid required authorizations are handled by
/// eligibility checks before state execution.
///
/// Local persistence failures require recovery and cannot be recorded as a state rejection.
///
/// Rejection carries the reported state failure.
///
/// Constructing either outcome does not prove execution, finality or successful note recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionOutcome {
    /// The occurrence passed the state rules and its effects were applied
    /// together as one atomic transition.
    Accepted,

    /// The occurrence failed a state rule and left state unchanged, including
    /// balances, fees, nonces, nullifiers and note outputs.
    Rejected(
        /// Reported state rule failure for this occurrence.
        ExecutionRejectionReason,
    ),
}
