//! Private sealed checkpoint capability with immutable retry cloning.

use super::data::PreparedData;
use crate::{
    EffectRecord, ExecutionArtifact, LogicalState, ParentToken, SourceCursor,
    state::CommittedRecord,
};
use houseki_types::Receipt;
use std::{fmt, sync::Arc};

/// A complete immutable candidate that has not been published or finalized.
///
/// Cloning retains this exact candidate for a later idempotent commit retry.
///
/// ```compile_fail
/// use houseki_ledger::PreparedCheckpoint;
/// let forged = PreparedCheckpoint {};
/// ```
#[derive(Clone)]
#[must_use]
pub struct PreparedCheckpoint {
    /// Shared complete candidate sealed only by the validating batch orchestrator.
    pub(crate) data: Arc<PreparedData>,
}

impl PreparedCheckpoint {
    /// Seals complete owned records only inside the validating preparation component.
    pub(super) fn seal(
        expected_parent: ParentToken,
        record: CommittedRecord,
        metrics: super::PreparationMetrics,
    ) -> Self {
        Self {
            data: Arc::new(PreparedData {
                expected_parent,
                record: Arc::new(record),
                metrics,
            }),
        }
    }

    /// Borrows local phase observations that are never part of canonical checkpoint
    /// bytes.
    pub fn metrics(&self) -> &super::PreparationMetrics {
        &self.data.metrics
    }

    /// Borrows the reproducible native summary without a committed status claim.
    pub fn artifact(&self) -> &ExecutionArtifact {
        self.data
            .record
            .artifact
            .as_ref()
            .expect("prepared records always have an artifact")
    }

    /// Borrows every original order occurrence receipt.
    pub fn receipts(&self) -> &[Receipt] {
        &self.data.record.receipts
    }

    /// Borrows every aligned public state effect.
    pub fn effects(&self) -> &[EffectRecord] {
        &self.data.record.effects
    }

    /// Borrows the complete parent comparison token.
    pub fn expected_parent(&self) -> &ParentToken {
        &self.data.expected_parent
    }

    /// Borrows the exact source progress that would be published.
    pub fn next_cursor(&self) -> &SourceCursor {
        self.data.record.head.source_cursor()
    }

    /// Borrows disposable post state for preview without publishing it.
    pub fn post_state(&self) -> &LogicalState {
        &self.data.record.state
    }
}

impl fmt::Debug for PreparedCheckpoint {
    /// Formats public identity and expected parent without cloning complete inputs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedCheckpoint")
            .field("artifact", &self.artifact().identity())
            .field("expected_parent", self.expected_parent())
            .finish()
    }
}
