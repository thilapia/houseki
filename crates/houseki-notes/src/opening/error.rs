//! Errors from checking private note opening storage and internal plaintext records.

use houseki_types::AmountError;
use thiserror::Error;

use crate::NoteFormatError;

/// A failure to establish the storage invariants of an ordinary note opening.
#[derive(Debug, Error)]
pub enum NoteOpeningError {
    /// The supplied amount is zero rather than a positive ordinary note value.
    #[error("ordinary note amount must be positive")]
    ZeroAmount,
}

/// An internal plaintext failure that never includes amount, blinding or raw record bytes.
#[derive(Debug, Error)]
pub(crate) enum NotePlaintextError {
    /// The record does not have the exact supported plaintext length.
    #[error("invalid note plaintext length {actual}")]
    InvalidLength {
        /// Complete supplied byte count.
        actual: usize,
    },

    /// The complete note version has no supported immutable rules.
    #[error(transparent)]
    UnsupportedFormat(
        /// Original format error retaining the complete identifier.
        #[from]
        NoteFormatError,
    ),

    /// The encoded atom count exceeds the shared amount bound.
    #[error(transparent)]
    InvalidAmount(
        /// Original bounded amount failure without the rejected value.
        #[from]
        AmountError,
    ),

    /// The decoded fields fail the ordinary opening storage rules.
    #[error(transparent)]
    InvalidOpening(
        /// Original opening failure without private material.
        #[from]
        NoteOpeningError,
    ),
}
