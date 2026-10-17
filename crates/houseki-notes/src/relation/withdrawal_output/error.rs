//! Failures of the native withdrawal output relation.

use houseki_crypto::CryptoFramingError;
use thiserror::Error;

/// A failure of the withdrawal output relation without private opening values.
#[derive(Debug, Error)]
pub enum WithdrawalOutputRelationError {
    /// The opening belongs to another network than the declared withdrawal.
    #[error("note opening network does not match the withdrawal")]
    NetworkMismatch,

    /// The opening does not derive the published output commitment.
    #[error("note opening does not match the withdrawal output commitment")]
    CommitmentMismatch,

    /// The matched opening amount differs from the positive public withdrawal amount.
    #[error("note opening amount does not match the public withdrawal amount")]
    AmountMismatch,

    /// Recipient binding or commitment framing failed without returning a digest.
    #[error("could not derive withdrawal output commitment: {0}")]
    CommitmentFraming(
        /// Original framing failure without private opening material.
        #[from]
        CryptoFramingError,
    ),
}
