//! Bounded provenance retained after complete fixture manifest validation.

use crate::FixtureUnitId;

/// Minimal immutable metadata retained after complete manifest validation.
#[derive(Debug, Clone)]
pub(super) struct UnitMetadata {
    /// Exact complete unit identity.
    pub(super) identity: FixtureUnitId,

    /// Manifest authenticated preceding identity.
    pub(super) previous: FixtureUnitId,

    /// Number of complete occurrences declared by this unit.
    pub(super) count: u64,
}
