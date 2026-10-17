//! Canonical address text and recipient validation failures.

use crate::NoteRecipientError;
use houseki_crypto::CryptoFramingError;
use thiserror::Error;

/// A failure to decode one exact canonical complete address string.
#[derive(Debug, Error)]
pub enum NoteAddressError {
    /// The string has a noncanonical length, prefix, alphabet, separator or checksum syntax.
    #[error("invalid canonical note address text")]
    InvalidText,

    /// The transcription checksum does not match the complete descriptor bytes.
    #[error("note address checksum mismatch")]
    ChecksumMismatch,

    /// Descriptor validation failed after complete text and checksum checks.
    #[error("invalid note address recipient: {0}")]
    Recipient(
        /// Original safe recipient validation failure.
        #[from]
        NoteRecipientError,
    ),

    /// Fixed checksum framing failed without accepting the address.
    #[error("could not derive note address checksum: {0}")]
    Framing(
        /// Original safe framing failure.
        #[from]
        CryptoFramingError,
    ),
}
