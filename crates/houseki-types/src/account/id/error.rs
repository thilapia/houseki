//! Errors when constructing a [`RewardAccountId`](super::RewardAccountId).

use thiserror::Error;

/// Errors when constructing a [`RewardAccountId`](super::RewardAccountId).
#[derive(Debug, Error)]
pub enum RewardAccountIdError {
    /// The reward account identifier does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a reward account identifier, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
