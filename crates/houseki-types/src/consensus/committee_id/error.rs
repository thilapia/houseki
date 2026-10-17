//! Errors when constructing a [`CommitteeId`](super::CommitteeId).

use thiserror::Error;

/// Errors when constructing a [`CommitteeId`](super::CommitteeId).
#[derive(Debug, Error)]
pub enum CommitteeIdError {
    /// The committee identifier does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a committee identifier, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
