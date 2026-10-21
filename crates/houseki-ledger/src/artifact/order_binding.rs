//! Public representation of the canonical order binding record.

use crate::{FixtureStreamId, FixtureUnitId};

/// Unverified order binding fields with no publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderBinding {
    /// Finite fixture stream identity.
    pub stream_id: FixtureStreamId,

    /// Complete source unit identity.
    pub unit_id: FixtureUnitId,

    /// Inclusive consumed range start.
    pub start_offset: u64,

    /// Exclusive consumed range end.
    pub end_offset: u64,

    /// Complete authenticated unit occurrence count.
    pub unit_occurrence_count: u64,
}
