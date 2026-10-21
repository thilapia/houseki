//! Committed checkpoint identity and source continuation.

use crate::{ExecutionArtifactId, SourceCursor, StateCommitment};
use houseki_types::CheckpointSequence;

/// Complete operational head published together with its logical state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadRecord {
    /// Position of this checkpoint in the execution history.
    pub(crate) sequence: CheckpointSequence,

    /// Complete local artifact identity.
    pub(crate) artifact_id: ExecutionArtifactId,

    /// Complete reference logical state commitment.
    pub(crate) state_commitment: StateCommitment,

    /// Exact persisted next source position.
    pub(crate) source_cursor: SourceCursor,
}

impl HeadRecord {
    /// Returns the committed sequence.
    pub const fn sequence(&self) -> CheckpointSequence {
        self.sequence
    }

    /// Returns the local artifact identity without a consensus finality claim.
    pub const fn artifact_id(&self) -> ExecutionArtifactId {
        self.artifact_id
    }

    /// Returns the committed logical state digest.
    pub const fn state_commitment(&self) -> StateCommitment {
        self.state_commitment
    }

    /// Borrows the exact source continuation.
    pub const fn source_cursor(&self) -> &SourceCursor {
        &self.source_cursor
    }
}
