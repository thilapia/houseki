//! Untrusted expected checkpoint representation used only for replay comparison.

use crate::{ArtifactHeader, EffectRecord, SnapshotRecord, SourceCursor};
use houseki_types::{NoteCommitment, Receipt};

/// Complete public comparison target whose fields confer no execution authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedCheckpoint {
    /// Canonical acyclic execution header.
    pub(crate) header: ArtifactHeader,

    /// Complete ordered reported outcomes.
    pub(crate) receipts: Vec<Receipt>,

    /// Complete ordered reported public effects.
    pub(crate) effects: Vec<EffectRecord>,

    /// Complete reported logical state representation.
    pub(crate) state: SnapshotRecord,

    /// Original ordered leaves required to independently rebuild the tree.
    pub(crate) leaves: Vec<NoteCommitment>,

    /// Exact reported source continuation.
    pub(crate) cursor: SourceCursor,
}

impl ExpectedCheckpoint {
    /// Compares full canonical reported state and effects against an independently computed record.
    pub(crate) fn matches_record(
        &self,
        record: &crate::state::CommittedRecord,
    ) -> Result<bool, crate::ArtifactError> {
        let Some(artifact) = record.artifact.as_ref() else {
            return Ok(false);
        };
        Ok(self.header == *artifact.header()
            && self.receipts == record.receipts
            && self.effects == record.effects
            && self.leaves == record.state.leaves()
            && self.cursor == *record.head.source_cursor()
            && crate::encode_snapshot(&self.state)?
                == crate::encode_snapshot(&crate::SnapshotRecord::from_state(&record.state)?)?)
    }
}
