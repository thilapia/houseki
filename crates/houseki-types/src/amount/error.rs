//! Errors when constructing or operating on an [`Amount`](super::Amount).

use thiserror::Error;

/// Errors when constructing or operating on an [`Amount`](super::Amount).
#[derive(Debug, Error)]
pub enum AmountError {
    /// The integer operation exceeded the range of `u128`.
    #[error("the numeric operation overflowed")]
    ValueOverflow,

    /// Subtraction would produce a negative amount.
    #[error("the numeric operation underflowed")]
    ValueUnderflow,

    /// The value exceeds the protocol's `10^29`-atom cap.
    #[error("the amount exceeds the maximum allowed value")]
    ValueExceedsMaximum,

    /// The text is not an unsigned decimal coin amount.
    #[error("invalid decimal amount")]
    InvalidDecimal,

    /// The fractional part has more than 20 digits, including trailing zeroes.
    #[error("the amount has more than 20 decimal places")]
    TooManyDecimalPlaces,

    /// An encoded atom count did not contain exactly 16 bytes.
    #[error("expected 16 amount bytes, got {actual}")]
    InvalidByteLength {
        /// Number of bytes supplied to the decoder.
        actual: usize,
    },
}
