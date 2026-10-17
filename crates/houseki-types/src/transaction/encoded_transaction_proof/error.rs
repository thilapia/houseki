//! Errors when constructing [`EncodedTransactionProof`](super::EncodedTransactionProof).

use thiserror::Error;

/// Errors when constructing [`EncodedTransactionProof`](super::EncodedTransactionProof).
#[derive(Debug, Error)]
pub enum EncodedTransactionProofError {
    /// The encoded proof exceeds the supplied inclusive byte limit.
    #[error("transaction proof length {actual} exceeds the maximum of {maximum} bytes")]
    ByteLengthExceedsLimit {
        /// The number of supplied proof bytes.
        actual: usize,

        /// The supplied inclusive maximum proof length in bytes.
        maximum: usize,
    },
}
