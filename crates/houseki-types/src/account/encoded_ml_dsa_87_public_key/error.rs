//! Errors when constructing an [`EncodedMlDsa87PublicKey`](super::EncodedMlDsa87PublicKey).

use thiserror::Error;

/// Errors when constructing an [`EncodedMlDsa87PublicKey`](super::EncodedMlDsa87PublicKey).
#[derive(Debug, Error)]
pub enum EncodedMlDsa87PublicKeyError {
    /// The encoded key does not contain exactly 2592 bytes.
    #[error("expected 2592 bytes for an encoded ML-DSA-87 public key, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
