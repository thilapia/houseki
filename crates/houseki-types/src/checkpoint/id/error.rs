//! Errors when constructing a [`CheckpointId`](super::CheckpointId).

use thiserror::Error;

/// Errors when constructing a [`CheckpointId`](super::CheckpointId).
#[derive(Debug, Error)]
pub enum CheckpointIdError {
    /// The checkpoint identifier does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a checkpoint identifier, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
