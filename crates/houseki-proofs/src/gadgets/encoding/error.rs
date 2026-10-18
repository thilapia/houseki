//! Redacted failures from assigning constrained representations.

/// Assignment failures that retain no private input or intermediate values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum EncodingError {
    /// The canonical input field value is outside the byte range.
    #[error("encoding input is not a byte")]
    InvalidByte,
}
