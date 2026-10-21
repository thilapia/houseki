//! Immutable trusted parent ownership for native preparation.

use super::{HeadRecord, LogicalState, ParentToken, ReplayInputs};
use crate::{EffectRecord, ExecutionArtifact};
use houseki_types::Receipt;
use std::sync::Arc;

/// Consistent immutable checkpoint view sealed by validated bootstrap or publication.
#[derive(Clone)]
pub struct ParentSnapshot {
    /// Shared complete store image retained while readers hold an old snapshot.
    pub(crate) image: Arc<crate::store::StoreImage>,
}

impl ParentSnapshot {
    /// Borrows the actual complete logical state.
    pub fn state(&self) -> &LogicalState {
        &self.image.current.state
    }

    /// Borrows the committed operational head.
    pub fn head(&self) -> &HeadRecord {
        &self.image.current.head
    }

    /// Copies all expected parent fields for a later compare and publish attempt.
    pub fn token(&self) -> ParentToken {
        ParentToken {
            head: self.image.current.head.clone(),
        }
    }

    /// Borrows an execution artifact when the checkpoint follows bootstrap.
    pub fn artifact(&self) -> Option<&ExecutionArtifact> {
        self.image.current.artifact.as_ref()
    }

    /// Borrows complete canonical receipts.
    pub fn receipts(&self) -> &[Receipt] {
        &self.image.current.receipts
    }

    /// Borrows the aligned public effects.
    pub fn effects(&self) -> &[EffectRecord] {
        &self.image.current.effects
    }

    /// Borrows all unit identities bound by the original independently expected source
    /// stream.
    pub(crate) fn source_unit_ids(&self) -> &[crate::FixtureUnitId] {
        match self.replay_inputs() {
            ReplayInputs::Bootstrap(m) => &m.fixture_unit_ids,
            ReplayInputs::Execution { unit_ids, .. } => unit_ids,
        }
    }

    /// Borrows this snapshot's complete consistent replay archive.
    pub fn archive(&self) -> &crate::ReplayArchive {
        &self.image.history
    }

    /// Iterates independently authenticated historical descriptors, including pruned
    /// anchors.
    pub(crate) fn known_anchors(&self) -> impl Iterator<Item = houseki_types::NoteTreeAnchor> + '_ {
        self.image
            .history
            .anchors
            .iter()
            .map(crate::AnchorRecord::anchor)
    }

    /// Borrows immutable public replay prerequisites.
    pub fn replay_inputs(&self) -> &ReplayInputs {
        &self.image.current.replay_inputs
    }
}
