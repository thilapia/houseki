//! Reported execution outcomes linked to vertex payload occurrences.

use crate::{ExecutionOutcome, VertexId};

/// The reported state outcome of a transaction occurrence within a checkpoint.
///
/// The vertex identifier and zero based transaction index refer to the same
/// payload position as an [`Occurrence`](crate::Occurrence). They distinguish
/// copies of a transaction in different vertices or payload positions, which
/// can have different outcomes. The index is local to the vertex and does not
/// specify canonical execution order.
///
/// The containing checkpoint's ordered receipt list supplies execution position
/// and checkpoint context. Consumers must bind each receipt to the matching
/// authenticated occurrence at that position and account for every occurrence,
/// including rejections. This record alone is not a globally unique execution
/// reference and carries no checkpoint membership evidence.
///
/// Acceptance reports an atomic state transition. Rejection carries a state
/// failure and reports that all effects, including fees, were left unapplied.
/// Invalid cryptography is handled before state execution, and local storage
/// failures require recovery rather than a different canonical receipt.
///
/// Construction preserves the declared fields without checking index bounds,
/// occurrence binding or execution. Every index value is representable. Wire
/// encoding, receipt commitments and rejection check precedence remain to be
/// specified. This value proves neither execution nor finality or note recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Receipt {
    vertex_id: VertexId,
    transaction_index: u64,
    outcome: ExecutionOutcome,
}

impl Receipt {
    /// Groups an occurrence reference and reported outcome without verifying them.
    pub const fn new(
        vertex_id: VertexId,
        transaction_index: u64,
        outcome: ExecutionOutcome,
    ) -> Self {
        Self {
            vertex_id,
            transaction_index,
            outcome,
        }
    }

    /// Returns the identifier of the declared containing vertex.
    pub const fn vertex_id(&self) -> VertexId {
        self.vertex_id
    }

    /// Returns the zero based transaction position within the vertex payload.
    pub const fn transaction_index(&self) -> u64 {
        self.transaction_index
    }

    /// Returns the reported state execution outcome.
    pub const fn outcome(&self) -> ExecutionOutcome {
        self.outcome
    }

    /// Consumes the receipt and returns its declared fields in constructor order.
    pub const fn into_parts(self) -> (VertexId, u64, ExecutionOutcome) {
        (self.vertex_id, self.transaction_index, self.outcome)
    }
}
