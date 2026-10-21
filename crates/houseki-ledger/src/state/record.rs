//! Complete immutable state, artifacts and replay inputs retained by a store image.

use super::{HeadRecord, LogicalState, ReplayInputs};
use crate::{EffectRecord, ExecutionArtifact};
use houseki_types::Receipt;

/// State, head, occurrence outcomes and replay inputs share one immutable owner.
pub(crate) struct CommittedRecord {
    /// Complete actual logical state at this checkpoint.
    pub(crate) state: LogicalState,

    /// Complete operational checkpoint identity.
    pub(crate) head: HeadRecord,

    /// Execution artifact, absent only for bootstrap.
    pub(crate) artifact: Option<ExecutionArtifact>,

    /// One canonical reported outcome per executed occurrence.
    pub(crate) receipts: Vec<Receipt>,

    /// Public effects aligned with the receipt list.
    pub(crate) effects: Vec<EffectRecord>,

    /// Complete immutable prerequisites for independent replay.
    pub(crate) replay_inputs: ReplayInputs,
}
