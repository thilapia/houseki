use thiserror::Error;

/// Errors when constructing an [`EncodedMlDsa87Signature`](super::EncodedMlDsa87Signature).
#[derive(Debug, Error)]
pub enum EncodedMlDsa87SignatureError {
    /// The encoded signature does not contain exactly 4627 bytes.
    #[error("expected 4627 bytes for an encoded ML-DSA-87 signature, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
