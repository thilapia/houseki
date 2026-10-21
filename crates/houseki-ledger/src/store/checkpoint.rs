//! Actual historical checkpoint ownership and context preserving queries.

use super::{AcceptedOutput, StoreImage, projection};
use crate::{EffectRecord, ExecutionArtifact, HeadRecord, LogicalState, state::CommittedRecord};
use houseki_types::{ExecutionProofStatus, FinalityStatus, Receipt};
use std::{fmt, sync::Arc};

/// Immutable actual historical checkpoint without a global freshness claim.
#[derive(Clone)]
pub struct CommittedCheckpoint {
    /// Complete consistent query image retained by the handle.
    pub(super) image: Arc<StoreImage>,

    /// Exact actual historical record selected within the retained native archive.
    pub(super) record: Arc<CommittedRecord>,
}

impl CommittedCheckpoint {
    /// Borrows the actual executed artifact.
    pub fn artifact(&self) -> &ExecutionArtifact {
        self.record
            .artifact
            .as_ref()
            .expect("committed query handles exclude bootstrap")
    }

    /// Borrows this historical checkpoint's actual logical state.
    pub fn state(&self) -> &LogicalState {
        &self.record.state
    }

    /// Borrows this historical checkpoint's complete operational head.
    pub fn head(&self) -> &HeadRecord {
        &self.record.head
    }

    /// Borrows every ordered reported occurrence outcome.
    pub fn receipts(&self) -> &[Receipt] {
        &self.record.receipts
    }

    /// Borrows every aligned public effect.
    pub fn effects(&self) -> &[EffectRecord] {
        &self.record.effects
    }

    /// Iterates exactly the accepted appends with original canonical recovery context.
    pub fn accepted_outputs(&self) -> impl Iterator<Item = AcceptedOutput<'_>> + '_ {
        projection::accepted_outputs(self)
    }

    /// Reports that local fixture publication establishes no consensus finality.
    pub const fn finality_status(&self) -> FinalityStatus {
        FinalityStatus::Unconfirmed
    }

    /// Reports that no complete checkpoint execution proof package was verified.
    pub const fn execution_proof_status(&self) -> ExecutionProofStatus {
        ExecutionProofStatus::Unverified
    }

    /// Returns the number of checkpoints available in this handle's consistent query
    /// image.
    pub fn retained_checkpoint_count(&self) -> usize {
        self.image.history.checkpoint_count()
    }
}

impl fmt::Debug for CommittedCheckpoint {
    /// Formats only public checkpoint identity and sequence.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommittedCheckpoint")
            .field("identity", &self.artifact().identity())
            .field("sequence", &self.head().sequence())
            .finish()
    }
}
