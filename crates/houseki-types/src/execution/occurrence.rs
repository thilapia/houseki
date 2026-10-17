//! Declared transaction occurrences within DAG vertex payloads.

use crate::{CommitteeContext, TransactionEnvelope, ValidatorId, VertexId};

/// A complete transaction envelope at a declared position in a DAG vertex.
///
/// The vertex author and committee context identify the validator and snapshot whose
/// authenticated reward mapping execution uses for fee attribution.
///
/// The transaction index is a zero based position within that vertex's ordered payload, not a
/// position in the canonical checkpoint execution order.
///
/// Construction preserves the declared fields without checking vertex contents, index bounds,
/// author identity or committee authorization.
///
/// Consumers must bind the complete envelope and its position to the authenticated vertex,
/// verify cryptographic eligibility and supply canonical order before state execution.
///
/// Every index value is representable, without setting a payload size limit or wire encoding.
///
/// An index must be checked before conversion to a host index.
///
/// The same transaction can occur in multiple vertices or payload positions.
///
/// Each occurrence must be considered under the execution rules, and only the first successfully
/// executing occurrence earns the fee.
///
/// This record performs no deduplication and establishes neither acceptance nor consensus
/// finality.
///
/// Equality compares all declared fields, including authorization bytes in the envelope, rather
/// than only semantic transaction identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Occurrence {
    /// Declared vertex containing this payload occurrence.
    vertex_id: VertexId,

    /// Declared validator whose authenticated mapping determines fee attribution.
    vertex_author: ValidatorId,

    /// Declared epoch and committee snapshot for author authentication.
    committee_context: CommitteeContext,

    /// Zero based payload position within the declared vertex.
    transaction_index: u64,

    /// Complete declared transaction, including its authorization bytes.
    envelope: TransactionEnvelope,
}

impl Occurrence {
    /// Groups the declared occurrence fields without authenticating them.
    pub const fn new(
        vertex_id: VertexId,
        vertex_author: ValidatorId,
        committee_context: CommitteeContext,
        transaction_index: u64,
        envelope: TransactionEnvelope,
    ) -> Self {
        Self {
            vertex_id,
            vertex_author,
            committee_context,
            transaction_index,
            envelope,
        }
    }

    /// Returns the identifier of the declared containing vertex.
    pub const fn vertex_id(&self) -> VertexId {
        self.vertex_id
    }

    /// Returns the declared vertex author.
    pub const fn vertex_author(&self) -> ValidatorId {
        self.vertex_author
    }

    /// Returns the declared epoch and committee snapshot context.
    pub const fn committee_context(&self) -> CommitteeContext {
        self.committee_context
    }

    /// Returns the zero based transaction position within the vertex payload.
    pub const fn transaction_index(&self) -> u64 {
        self.transaction_index
    }

    /// Borrows the complete declared transaction envelope.
    pub const fn envelope(&self) -> &TransactionEnvelope {
        &self.envelope
    }

    /// Consumes the occurrence and returns its declared fields in constructor order.
    pub fn into_parts(
        self,
    ) -> (
        VertexId,
        ValidatorId,
        CommitteeContext,
        u64,
        TransactionEnvelope,
    ) {
        (
            self.vertex_id,
            self.vertex_author,
            self.committee_context,
            self.transaction_index,
            self.envelope,
        )
    }
}
