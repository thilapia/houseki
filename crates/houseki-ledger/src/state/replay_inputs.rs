//! Immutable public inputs retained independently of temporary verification evidence.

use crate::BootstrapManifest;
use houseki_types::NoteTreeAnchor;
use std::sync::Arc;

/// Complete public prerequisites for reconstructing a reference checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayInputs {
    /// Validated original bootstrap declarations retained under explicit fixture trust.
    Bootstrap(
        /// Complete public manifest with the independently expected commitment.
        Arc<BootstrapManifest>,
    ),

    /// Complete source bytes and authenticated historical metadata for execution
    /// replay.
    Execution {
        /// Canonical complete source unit including envelopes and origin metadata.
        source_unit: Arc<[u8]>,

        /// Complete finite unit identity list authenticated by the expected stream.
        unit_ids: Arc<[crate::FixtureUnitId]>,

        /// Independently authenticated descriptors retained beyond eligibility
        /// pruning.
        trusted_anchors: Arc<[NoteTreeAnchor]>,
    },
}
