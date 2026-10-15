use thiserror::Error;

/// Errors when constructing a [`NetworkId`](super::NetworkId).
#[derive(Debug, Error)]
pub enum NetworkIdError {
    /// The genesis commitment does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a network identifier, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
