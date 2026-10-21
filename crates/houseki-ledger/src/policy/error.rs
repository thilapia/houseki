//! Failures owned by policy validation and checkpoint rule derivation.

/// Invalid policy, unsupported native shape or exhausted arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// A policy would exceed the absolute bounded reference implementation envelope.
    #[error("policy exceeds reference resource bounds")]
    ResourceBounds,

    /// Local bounded rule metadata could not be reserved.
    #[error("policy metadata allocation failed")]
    Allocation,

    /// Actual payment counts exceed the supported wallet relation.
    #[error("unsupported payment shape")]
    UnsupportedShape,

    /// Full width fee arithmetic exceeds a represented amount.
    #[error("required fee exceeds amount bounds")]
    FeeOverflow,

    /// The fixed development schedule identifier carries different rates.
    #[error("fee schedule identity does not match its rates")]
    FeeScheduleIdentity,

    /// Anchor retention cannot preserve the complete positive eligibility window.
    #[error("invalid anchor window or retention")]
    AnchorRetention,

    /// The parent checkpoint has no numeric successor.
    #[error("checkpoint sequence is exhausted")]
    SequenceExhausted,
}
