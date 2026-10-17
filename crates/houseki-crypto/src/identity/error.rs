//! Canonical body encoding and transaction identity framing failures.

use crate::CryptoFramingError;
use houseki_types::BodyCodecError;
use thiserror::Error;

/// A failure to encode or frame the actual body for transaction identification.
#[derive(Debug, Error)]
pub enum BodyHashError {
    /// Active bounds or canonical representation prevented complete body encoding.
    #[error("could not encode transaction body: {0}")]
    Encoding(
        /// Original bounded canonical codec failure.
        #[from]
        BodyCodecError,
    ),

    /// Fixed domain framing failed without returning an identifier.
    #[error("could not frame transaction identity: {0}")]
    Framing(
        /// Original safe framing failure.
        #[from]
        CryptoFramingError,
    ),
}
