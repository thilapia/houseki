//! Errors when constructing [`EncryptedNoteEnvelope`](super::EncryptedNoteEnvelope).

use thiserror::Error;

/// Errors when constructing [`EncryptedNoteEnvelope`](super::EncryptedNoteEnvelope).
#[derive(Debug, Error)]
pub enum EncryptedNoteEnvelopeError {
    /// The opaque payload exceeds the supplied inclusive byte limit.
    #[error("encrypted note payload length {actual} exceeds the maximum of {maximum} bytes")]
    PayloadLengthExceedsLimit {
        /// The number of supplied payload bytes.
        actual: usize,

        /// The supplied inclusive maximum payload length in bytes.
        maximum: usize,
    },
}
