//! Declared committee context for consensus and execution.

use crate::{CommitteeId, Epoch};

/// An epoch paired with the identifier of its declared committee snapshot.
///
/// The snapshot identifies the validator identities, consensus signing keys,
/// voting weights and reward mappings used to interpret an occurrence's author.
/// Keeping its identifier alongside the epoch names the exact snapshot without
/// assuming that an epoch number alone determines all committee data.
///
/// Construction preserves both values without checking that the snapshot is
/// authorized for that epoch. Consumers must resolve and authenticate it under
/// the intended network's state and transition rules before using its keys,
/// weights or reward mappings. This context carries no snapshot or verification
/// evidence and establishes neither author eligibility nor consensus finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitteeContext {
    epoch: Epoch,
    committee_id: CommitteeId,
}

impl CommitteeContext {
    /// Groups the declared epoch and snapshot identifier without authenticating them.
    pub const fn new(epoch: Epoch, committee_id: CommitteeId) -> Self {
        Self {
            epoch,
            committee_id,
        }
    }

    /// Returns the declared validator epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the declared committee snapshot identifier.
    pub const fn committee_id(&self) -> CommitteeId {
        self.committee_id
    }

    /// Consumes the context and returns its epoch and snapshot identifier.
    pub const fn into_parts(self) -> (Epoch, CommitteeId) {
        (self.epoch, self.committee_id)
    }
}
