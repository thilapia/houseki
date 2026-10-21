//! Public representation of the canonical effect record.

use crate::AcceptedEffect;
use houseki_types::VertexId;

/// Unverified effect fields with no publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectRecord {
    /// Origin vertex identity.
    pub vertex_id: VertexId,

    /// Origin payload position.
    pub transaction_index: u64,

    /// Accepted effects or an empty rejection.
    pub accepted: Option<AcceptedEffect>,
}
