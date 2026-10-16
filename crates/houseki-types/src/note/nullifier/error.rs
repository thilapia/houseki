use thiserror::Error;

/// Errors when constructing a [`Nullifier`](super::Nullifier).
#[derive(Debug, Error)]
pub enum NullifierError {
    /// The nullifier does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a nullifier, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
