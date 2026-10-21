//! Complete immutable next record owner and exact parent comparison token.

use crate::{ParentToken, state::CommittedRecord};
use std::sync::Arc;

/// Complete prepared publication data without references to a proof runtime.
pub(crate) struct PreparedData {
    /// Full expected parent identity, including exact source progress.
    pub(crate) expected_parent: ParentToken,

    /// Complete immutable state, head, artifact, outcomes and public replay inputs.
    pub(crate) record: Arc<CommittedRecord>,

    /// Operational diagnostics excluded from every committed record and identity.
    pub(crate) metrics: super::PreparationMetrics,
}
