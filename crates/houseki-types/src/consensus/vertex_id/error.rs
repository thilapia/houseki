use thiserror::Error;

/// Errors when constructing a [`VertexId`](super::VertexId).
#[derive(Debug, Error)]
pub enum VertexIdError {
    /// The identifier does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a vertex identifier, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
