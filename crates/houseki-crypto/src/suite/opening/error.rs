//! Failures while opening a bounded note envelope without releasing unauthenticated bytes.

use crate::{CryptoFramingError, NotePayloadError};
use thiserror::Error;

/// A failure to recover authenticated note bytes from a complete envelope.
#[derive(Debug, Error)]
pub enum NoteDecryptionError {
    /// The public payload exceeds the active limit or lacks a recognized complete layout.
    #[error(transparent)]
    Payload(
        /// Original payload failure retaining its length or unsupported suite identifier.
        #[from]
        NotePayloadError,
    ),

    /// The ciphertext implies a message beyond an algorithm or host length bound.
    #[error("note decryption length exceeds an algorithm or host limit")]
    LengthLimitExceeded,

    /// Recipient binding or derivation inputs could not be encoded completely.
    #[error(transparent)]
    Framing(
        /// Original failure while encoding the cryptographic transcript.
        #[from]
        CryptoFramingError,
    ),

    /// The suite or recipient disagrees with the context, or ciphertext authentication fails.
    #[error("note authentication failed")]
    AuthenticationFailed,
}
