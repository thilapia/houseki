//! Public representation of the canonical header record.

use crate::{ExecutionArtifactId, ExecutionPolicyId, OrderBinding, StateCommitment};
use houseki_types::{CheckpointSequence, CommitteeContext, NetworkId};

/// Unverified header fields with no publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactHeader {
    /// Reference artifact schema code.
    pub schema: u32,

    /// Exact execution policy commitment.
    pub policy_id: ExecutionPolicyId,

    /// Network of the complete transition.
    pub network: NetworkId,

    /// Executed checkpoint position.
    pub sequence: CheckpointSequence,

    /// Fixed epoch and committee.
    pub committee_context: CommitteeContext,

    /// Previous artifact identity.
    pub parent_artifact_id: ExecutionArtifactId,

    /// Logical state commitment before execution.
    pub pre_state: StateCommitment,

    /// Logical state commitment after execution.
    pub post_state: StateCommitment,

    /// Exact consumed source range.
    pub order: OrderBinding,

    /// Complete ordered envelope commitment.
    pub occurrences_root: [u8; 64],

    /// Number of outcomes and effects.
    pub occurrence_count: u64,

    /// Complete ordered receipt commitment.
    pub receipts_root: [u8; 64],

    /// Complete public effect commitment.
    pub effects_root: [u8; 64],

    /// Fixed empty system event commitment.
    pub system_events_root: [u8; 64],
}
