//! Checkpoint positions associated with concrete note descriptors.

use houseki_types::{CheckpointSequence, NoteTreeAnchor};

/// A canonical historical anchor record without independent finality evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorRecord {
    /// Checkpoint where the descriptor was recorded.
    sequence: CheckpointSequence,

    /// Complete network, root and count metadata.
    anchor: NoteTreeAnchor,
}

impl AnchorRecord {
    /// Retains declared history metadata for later validation.
    pub const fn new(sequence: CheckpointSequence, anchor: NoteTreeAnchor) -> Self {
        Self { sequence, anchor }
    }

    /// Returns the historical checkpoint sequence.
    pub const fn sequence(&self) -> CheckpointSequence {
        self.sequence
    }

    /// Returns the complete note descriptor.
    pub const fn anchor(&self) -> NoteTreeAnchor {
        self.anchor
    }
}
