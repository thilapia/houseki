//! Errors when constructing an [`EncodedMlKem1024Ciphertext`](super::EncodedMlKem1024Ciphertext).

use thiserror::Error;

/// Errors when constructing an [`EncodedMlKem1024Ciphertext`](super::EncodedMlKem1024Ciphertext).
#[derive(Debug, Error)]
pub enum EncodedMlKem1024CiphertextError {
    /// The encapsulation ciphertext does not contain exactly 1568 bytes.
    #[error("expected 1568 bytes for an encoded ML-KEM-1024 ciphertext, got {actual}")]
    InvalidByteLength {
        /// The byte length of the supplied slice.
        actual: usize,
    },
}
