//! Failures to initialize, append or retrieve concrete note tree paths.

use houseki_crypto::{CryptoFramingError, NoteTreeHashError};
use thiserror::Error;

/// A failure to initialize, append or retrieve a concrete application tree path.
#[derive(Debug, Error)]
pub enum NoteTreeError {
    /// All 2^64 leaf positions are occupied.
    #[error("application note tree is full")]
    Full,

    /// The requested witness position has not been appended.
    #[error("note position is not occupied")]
    PositionNotOccupied,

    /// Sparse public node storage could not be reserved before an append.
    #[error("could not reserve application note tree storage")]
    AllocationFailed,

    /// Public parent hashing rejected its fixed tree inputs.
    #[error("could not hash application note tree parent: {0}")]
    Hash(
        /// Original public tree hash failure.
        #[from]
        NoteTreeHashError,
    ),

    /// Fixed leaf or root framing failed before state mutation.
    #[error("could not frame application note tree: {0}")]
    Framing(
        /// Original safe framing failure.
        #[from]
        CryptoFramingError,
    ),
}
