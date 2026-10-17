//! Redacted failures from assigning a packed recipient coefficient pair.

/// Assignment failures without encoded key bytes or coefficient values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RecipientKeyError {
    /// An input field cell is outside the canonical byte range.
    #[error("recipient key input is not a byte")]
    InvalidByte,

    /// An encoded polynomial coefficient exceeds the native canonical bound.
    #[error("recipient key coefficient is not canonical")]
    NonCanonicalCoefficient,
}
