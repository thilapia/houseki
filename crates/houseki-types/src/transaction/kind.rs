//! Operations represented by transaction bodies.

/// Identifies the operation a transaction requests.
///
/// Each kind has its own body, authorization requirements and execution rules.
/// The kind must be bound to the canonical body and its authorization so that
/// a transaction cannot be reinterpreted as a different operation.
///
/// These variants describe the payment and reward withdrawal flows currently
/// modeled by the protocol. They do not assign wire tags or establish that a
/// transaction is valid or supported under the active protocol rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionKind {
    /// Spends private notes to create one or more ordinary note outputs and pay
    /// a separate public fee. Input count, recipients and optional change do
    /// not introduce distinct transaction kinds.
    Payment,

    /// Withdraws public value from a reward account into one ordinary note
    /// output, with a separate public fee charged to the same account.
    RewardWithdrawal,
}
