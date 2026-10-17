//! Redacted failures from assigning integer arithmetic and amount bounds.

/// Assignment failures without private limbs, totals or intermediate values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AmountError {
    /// An input field cell is outside the canonical byte range.
    #[error("amount input is not a byte")]
    InvalidLimb,

    /// An exact sum exceeds the sixteen byte integer capacity.
    #[error("amount arithmetic exceeds integer capacity")]
    Overflow,
}
