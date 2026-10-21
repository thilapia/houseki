//! Public representation of the canonical append record.

use houseki_types::{NoteCommitment, NotePosition};

/// Unverified append fields with no publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteAppend {
    /// Actual assigned insertion position.
    pub position: NotePosition,

    /// Appended commitment including repeated values.
    pub commitment: NoteCommitment,
}
