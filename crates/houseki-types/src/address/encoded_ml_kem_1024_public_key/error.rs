//! Errors when constructing an [`EncodedMlKem1024PublicKey`](super::EncodedMlKem1024PublicKey).

use thiserror::Error;

/// Errors when constructing an [`EncodedMlKem1024PublicKey`](super::EncodedMlKem1024PublicKey).
#[derive(Debug, Error)]
pub enum EncodedMlKem1024PublicKeyError {
    /// The encoded key does not contain exactly 1568 bytes.
    #[error("expected 1568 bytes for an encoded ML-KEM-1024 public key, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
