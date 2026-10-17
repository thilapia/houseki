//! Declared network, occupied count and root for actual membership evaluation.

use crate::{NetworkId, NoteCount, NoteRoot};

/// A declared count bound application note tree anchor under one complete network.
///
/// Construction preserves metadata without authenticating its existence, finality or eligibility.
///
/// Native membership recomputes the complete count bound root, while ledger consumers authenticate
/// this exact anchor and check whether it is eligible for spending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoteTreeAnchor {
    /// Network bound into every tree hash.
    network: NetworkId,

    /// Bounded occupied leaf count included in the root transcript.
    count: NoteCount,

    /// Complete declared count bound root.
    root: NoteRoot,
}

impl NoteTreeAnchor {
    /// Retains all declared anchor metadata without performing a membership or state check.
    pub const fn new(network: NetworkId, count: NoteCount, root: NoteRoot) -> Self {
        Self {
            network,
            count,
            root,
        }
    }

    /// Returns the declared network.
    pub const fn network_id(&self) -> NetworkId {
        self.network
    }

    /// Returns the complete occupied count including a possible full tree.
    pub const fn count(&self) -> NoteCount {
        self.count
    }

    /// Returns the exact count bound root.
    pub const fn root(&self) -> NoteRoot {
        self.root
    }
}
