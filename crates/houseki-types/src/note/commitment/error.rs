use thiserror::Error;

/// Errors when constructing a [`NoteCommitment`](super::NoteCommitment).
#[derive(Debug, Error)]
pub enum NoteCommitmentError {
    /// The note commitment does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a note commitment, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
