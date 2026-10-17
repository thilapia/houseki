//! Capacity errors for the fixed depth application note tree.

use thiserror::Error;

/// A count outside the complete depth 64 note tree capacity.
#[derive(Debug, Error)]
#[error("note count exceeds the depth 64 tree capacity")]
pub struct NoteCountError;
