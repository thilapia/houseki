//! Exact expected-parent token for later compare-and-publish operations.

use super::HeadRecord;
use crate::{ExecutionArtifactId, SourceCursor, StateCommitment};
use houseki_types::CheckpointSequence;

/// Complete expected head identity with no caller-selected mutable fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentToken {
    /// Sequence, artifact, state root and cursor copied from a validated snapshot.
    pub(super) head: HeadRecord,
}

impl ParentToken {
    /// Returns the parent sequence.
    pub const fn sequence(&self) -> CheckpointSequence {
        self.head.sequence()
    }

    /// Returns the parent artifact identity.
    pub const fn artifact_id(&self) -> ExecutionArtifactId {
        self.head.artifact_id()
    }

    /// Returns the parent logical state commitment.
    pub const fn state_commitment(&self) -> StateCommitment {
        self.head.state_commitment()
    }

    /// Borrows the complete source continuation.
    pub const fn source_cursor(&self) -> &SourceCursor {
        self.head.source_cursor()
    }
}
