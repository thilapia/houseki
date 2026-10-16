//! Failures while sealing a bounded note envelope.

use thiserror::Error;

use crate::CryptoFramingError;

/// A failure to encrypt note bytes into a complete envelope.
#[derive(Debug, Error)]
pub enum NoteEncryptionError {
    /// The encoded payload would exceed the caller's active inclusive byte limit.
    #[error("note payload length {actual} exceeds the maximum of {maximum} bytes")]
    PayloadLengthExceedsLimit {
        /// Required bytes including the suite header, nonce, ciphertext and tag.
        actual: usize,

        /// Inclusive payload limit supplied by the caller.
        maximum: usize,
    },

    /// The message or complete payload exceeds an algorithm or host length bound.
    #[error("note encryption length exceeds an algorithm or host limit")]
    LengthLimitExceeded,

    /// The system source could not supply the complete nonce or encapsulation randomness.
    #[error("could not obtain randomness for note encryption")]
    RandomnessUnavailable,

    /// Recipient binding or derivation inputs could not be encoded completely.
    #[error(transparent)]
    Framing(
        /// Original failure while encoding the cryptographic transcript.
        #[from]
        CryptoFramingError,
    ),

    /// Authenticated encryption failed without returning an envelope.
    #[error("note encryption failed")]
    EncryptionFailed,
}
