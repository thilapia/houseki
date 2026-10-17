//! Native membership failures without private path values.

use houseki_crypto::CryptoFramingError;
use thiserror::Error;

/// A failure of actual native membership without exposing private path values.
#[derive(Debug, Error)]
pub enum NoteMembershipError {
    /// The original position is outside the anchor's occupied prefix.
    #[error("note position is not occupied under the anchor")]
    PositionNotOccupied,

    /// The full recomputed count bound root differs from the selected anchor.
    #[error("note membership root does not match the anchor")]
    RootMismatch,

    /// Fixed guarded tree framing failed without membership success.
    #[error("could not derive note membership root: {0}")]
    Framing(
        /// Original safe fixed framing failure.
        #[from]
        CryptoFramingError,
    ),
}

/// Failure to select a sibling without exposing private path material.
#[cfg(feature = "proofs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProofPathAccessError {
    /// The requested sibling level is outside the fixed depth 64 path.
    #[error("invalid proof path level")]
    InvalidLevel,
}
