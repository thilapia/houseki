//! Failures while generating fresh private note blinding.

use thiserror::Error;

/// A failure to obtain complete fresh note blinding from the system random source.
#[derive(Debug, Error)]
pub enum NoteBlindingError {
    /// The source failed to supply the complete buffer, possibly after writing secret bytes.
    #[error("could not obtain randomness for note blinding generation")]
    RandomnessUnavailable,
}
