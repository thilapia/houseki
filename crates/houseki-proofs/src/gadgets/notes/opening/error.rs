//! Redacted failures from assigning complete note-opening constraints.

use crate::gadgets::{AmountError, notes::RecipientKeyError};

/// Assignment errors without versions, key bytes, amounts or intermediate digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OpeningError {
    /// Destination storage does not contain complete bounded cycles.
    #[error("opening storage does not match its layout")]
    ShapeMismatch,

    /// An input field cell is outside the canonical byte range.
    #[error("opening input is not a byte")]
    InvalidByte,

    /// Note version, address format or suite differs from the fixed V1 identifiers.
    #[error("opening format is unsupported")]
    UnsupportedFormat,

    /// The amount violates the existing positive-note contract.
    #[error("opening amount is invalid")]
    InvalidAmount(#[from] AmountError),

    /// The key violates canonical coefficient encoding.
    #[error("opening recipient key is invalid")]
    InvalidRecipient(#[from] RecipientKeyError),
}
