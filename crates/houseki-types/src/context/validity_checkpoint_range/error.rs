//! Errors when constructing a [`ValidityCheckpointRange`](super::ValidityCheckpointRange).

use thiserror::Error;

/// Errors when constructing a [`ValidityCheckpointRange`](super::ValidityCheckpointRange).
#[derive(Debug, Error)]
pub enum ValidityCheckpointRangeError {
    /// The starting checkpoint is after the ending checkpoint.
    #[error("the starting checkpoint is after the ending checkpoint")]
    ReversedBounds,
}
