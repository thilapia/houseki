//! State rules that can reject an eligible transaction occurrence.

/// The reported reason an eligible occurrence left the ledger unchanged.
///
/// Execution checks the occurrence against the fixed checkpoint context and the state produced
/// by earlier accepted occurrences.
///
/// These reasons describe state failures after eligibility checks, so they do not include
/// malformed payloads, invalid proofs or invalid required authorizations.
///
/// Local storage failures require recovery and cannot be reported as a rejection reason.
///
/// This type names state failures without performing the checks.
///
/// Its variant order defines neither check precedence nor wire codes.
///
/// Those contracts must be specified before reasons are committed to canonical receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionRejectionReason {
    /// The declared network, protocol version or proof profile is not allowed
    /// by the checkpoint's execution context.
    UnsupportedContext,

    /// The executing checkpoint is before the inclusive start or after the
    /// inclusive end of the transaction's validity range.
    OutsideValidityRange,

    /// The payment's anchor is not allowed by the checkpoint's anchor policy.
    DisallowedAnchor,

    /// The declared fee schedule differs from the active schedule.
    WrongFeeSchedule,

    /// The public fee differs from the exact fee required by the active
    /// schedule for the transaction's kind and actual public workload.
    WrongFee,

    /// At least one input nullifier is already present in the evolving spent
    /// set, including nullifiers consumed earlier in the same checkpoint.
    SpentNullifier,

    /// The source reward account cannot cover the withdrawal amount plus its
    /// fee, even if that account would also receive the fee on acceptance.
    InsufficientBalance,

    /// The withdrawal nonce differs from the source account's next nonce.
    WrongNonce,

    /// The source account's withdrawal nonce has no successor, so a successful
    /// withdrawal could not advance it without wrapping.
    NonceExhausted,

    /// A proposed state change exceeds an arithmetic bound, account balance bound or note tree
    /// capacity.
    ///
    /// This refers to protocol bounds rather than the node's available memory or storage.
    StateBoundsExceeded,
}
