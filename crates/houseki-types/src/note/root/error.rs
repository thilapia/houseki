//! Errors when constructing a [`NoteRoot`](super::NoteRoot).

use thiserror::Error;

/// Errors when constructing a [`NoteRoot`](super::NoteRoot).
#[derive(Debug, Error)]
pub enum NoteRootError {
    /// The note tree root does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a note tree root, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
