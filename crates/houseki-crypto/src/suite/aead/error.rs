//! Errors from bounded note encryption and authenticated opening.

use thiserror::Error;

/// Failure to seal or authenticate bounded note bytes.
#[derive(Debug, Error, PartialEq, Eq)]
pub(in crate::suite) enum NoteAeadError {
    /// The plaintext length exceeds the caller's inclusive limit.
    #[error("plaintext length {actual} exceeds limit {maximum}")]
    PlaintextTooLong {
        /// Plaintext bytes supplied or implied by the ciphertext body.
        actual: usize,

        /// Inclusive plaintext limit supplied by the caller.
        maximum: usize,
    },

    /// A message, its tag or its associated data exceeds an algorithm or host bound.
    #[error("AEAD length exceeds an algorithm or host limit")]
    LengthLimitExceeded,

    /// The backend rejected sealing without returning ciphertext.
    #[error("note encryption failed")]
    EncryptionFailed,

    /// The input lacks a complete tag or fails authentication.
    #[error("note authentication failed")]
    AuthenticationFailed,
}
