//! Failures to evaluate fixed public note tree parents.

use crate::CryptoFramingError;
use thiserror::Error;

/// A failure to evaluate one fixed public tree parent.
#[derive(Debug, Error)]
pub enum NoteTreeHashError {
    /// Parent levels must be from zero through 63 inclusive.
    #[error("invalid note tree parent level {level}")]
    InvalidLevel {
        /// Complete supplied level without narrowing.
        level: u32,
    },

    /// Fixed tree framing failed without returning a node.
    #[error("could not frame note tree node: {0}")]
    Framing(
        /// Original safe framing failure.
        #[from]
        CryptoFramingError,
    ),
}
