//! Errors when constructing an [`OwnershipCommitment`](super::OwnershipCommitment).

use thiserror::Error;

/// Errors when constructing an [`OwnershipCommitment`](super::OwnershipCommitment).
#[derive(Debug, Error)]
pub enum OwnershipCommitmentError {
    /// The ownership commitment does not contain exactly 64 bytes.
    #[error("expected 64 bytes for an ownership commitment, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
