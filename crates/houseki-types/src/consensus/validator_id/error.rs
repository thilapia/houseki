use thiserror::Error;

/// Errors when constructing a [`ValidatorId`](super::ValidatorId).
#[derive(Debug, Error)]
pub enum ValidatorIdError {
    /// The validator identifier does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a validator identifier, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
