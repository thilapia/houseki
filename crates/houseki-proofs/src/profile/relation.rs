//! Operation tags used by trusted proof identities.

/// Supported operation names without an assertion that a profile is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum Relation {
    /// Knowledge of a complete payment's linked spends and outputs.
    Payment = 1,

    /// Knowledge of the single withdrawal output opening.
    RewardWithdrawal = 2,
}
