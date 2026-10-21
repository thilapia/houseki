//! Public representation of the canonical fixture stream record.

use crate::{ExecutionArtifactId, FixtureUnitId};
use houseki_types::NetworkId;

/// Unverified fixture stream fields with no publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureStreamRecord {
    /// Network bound to the stream.
    pub network: NetworkId,

    /// Trusted fixture starting checkpoint.
    pub starting_artifact_id: ExecutionArtifactId,

    /// Complete finite unit identities in ordinal order.
    pub unit_ids: Vec<FixtureUnitId>,
}
