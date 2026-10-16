//! Errors from checking private note opening storage.

use thiserror::Error;

/// A failure to establish the storage invariants of an ordinary note opening.
#[derive(Debug, Error)]
pub enum NoteOpeningError {
    /// The supplied amount is zero rather than a positive ordinary note value.
    #[error("ordinary note amount must be positive")]
    ZeroAmount,
}
