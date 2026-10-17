//! Failures to sign or verify complete canonical withdrawal bodies.

use crate::CryptoFramingError;
use houseki_types::BodyCodecError;
use thiserror::Error;

/// A failure to sign or verify the exact complete withdrawal body.
#[derive(Debug, Error)]
pub enum WithdrawalSignatureError {
    /// The supplied operational key differs from the body's declared authority.
    #[error("withdrawal signing authority does not match the body")]
    AuthorityMismatch,

    /// The complete canonical body cannot be encoded under active bounds.
    #[error("could not encode withdrawal signature body: {0}")]
    Encoding(
        /// Original bounded public encoding failure.
        #[from]
        BodyCodecError,
    ),

    /// Fixed application framing failed without a signature result.
    #[error("could not frame withdrawal signature body: {0}")]
    Framing(
        /// Original safe framing failure.
        #[from]
        CryptoFramingError,
    ),

    /// Fresh signing randomness could not be fully acquired.
    #[error("withdrawal signing randomness is unavailable")]
    RandomnessUnavailable,

    /// The signature encoding or direct contextual signature relationship is invalid.
    #[error("invalid withdrawal signature")]
    InvalidSignature,
}
