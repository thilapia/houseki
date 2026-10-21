//! Public representation of the canonical fixture unit record.

use crate::FixtureUnitId;
use houseki_types::Occurrence;

/// Unverified fixture unit fields with no publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureUnitRecord {
    /// Zero based unit position in the finite stream.
    pub ordinal: u64,

    /// Previous unit identity or zero for the first.
    pub previous_unit_id: FixtureUnitId,

    /// Complete ordered unverified occurrences.
    pub occurrences: Vec<Occurrence>,
}
