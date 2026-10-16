use thiserror::Error;

/// Errors when constructing a [`TransactionId`](super::TransactionId).
#[derive(Debug, Error)]
pub enum TransactionIdError {
    /// The identifier does not contain exactly 64 bytes.
    #[error("expected 64 bytes for a transaction identifier, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
