//! Validated representation awaiting independent state commitment comparison.

use crate::{LogicalState, SourceCursor};
use houseki_types::CheckpointSequence;

/// A consistent bootstrap representation that is not a trusted parent capability.
pub struct BootstrapCandidate {
    /// Rebuilt actual logical state.
    pub(crate) state: LogicalState,

    /// Declared bootstrap checkpoint sequence.
    pub(crate) sequence: CheckpointSequence,

    /// Declared parent artifact identity awaiting fixture trust establishment.
    pub(crate) parent_artifact_id: crate::ExecutionArtifactId,

    /// Independently supplied expected logical state digest.
    pub(crate) expected_state_commitment: crate::StateCommitment,

    /// Declared continuation awaiting source manifest validation.
    pub(crate) source_cursor: SourceCursor,
}

impl BootstrapCandidate {
    /// Borrows the fully rebuilt representation without authenticating its commitment.
    pub const fn state(&self) -> &LogicalState {
        &self.state
    }

    /// Returns the declared parent sequence.
    pub const fn sequence(&self) -> CheckpointSequence {
        self.sequence
    }

    /// Returns the complete declared parent artifact identity.
    pub const fn parent_artifact_id(&self) -> &crate::ExecutionArtifactId {
        &self.parent_artifact_id
    }

    /// Returns the independently expected state digest for the next validation stage.
    pub const fn expected_state_commitment(&self) -> &crate::StateCommitment {
        &self.expected_state_commitment
    }

    /// Borrows the declared source continuation.
    pub const fn source_cursor(&self) -> &SourceCursor {
        &self.source_cursor
    }
}
