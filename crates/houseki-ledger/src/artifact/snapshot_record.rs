//! Public representation of the canonical snapshot record.

use crate::{AnchorRecord, CommitteeEntry, ExecutionPolicy};
use houseki_types::{
    Amount, CommitteeContext, NetworkId, NoteTreeAnchor, Nullifier, RewardAccount, RewardAccountId,
};

/// Unverified snapshot record fields with no publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRecord {
    /// Declared logical network.
    pub network: NetworkId,

    /// Actual count bound root representing retained leaves.
    pub note_anchor: NoteTreeAnchor,

    /// Distinct markers sorted by complete bytes.
    pub spent: Vec<Nullifier>,

    /// Complete accounts sorted by full identity.
    pub accounts: Vec<(RewardAccountId, RewardAccount)>,

    /// Canonical historical descriptors in sequence order.
    pub anchors: Vec<AnchorRecord>,

    /// Complete active execution policy.
    pub policy: ExecutionPolicy,

    /// Fixed epoch and committee identity.
    pub committee_context: CommitteeContext,

    /// Complete registrations sorted by validator identity.
    pub committee: Vec<CommitteeEntry>,

    /// Aggregate shielded amount.
    pub pool: Amount,

    /// Fixed bootstrap supply.
    pub issued: Amount,
}

impl SnapshotRecord {
    /// Copies bounded complete logical records for canonical encoding without
    /// conferring trust.
    ///
    /// # Errors
    ///
    /// Reports local allocation failure before exposing a partial record list.
    pub fn from_state(state: &crate::LogicalState) -> Result<Self, crate::ArtifactError> {
        let mut spent = Vec::new();
        spent
            .try_reserve_exact(state.spent.len())
            .map_err(|_| crate::ArtifactError::Allocation)?;
        spent.extend(state.spent().copied());

        let mut accounts = Vec::new();
        accounts
            .try_reserve_exact(state.accounts.len())
            .map_err(|_| crate::ArtifactError::Allocation)?;
        accounts.extend(
            state
                .accounts()
                .map(|(id, a)| (RewardAccountId::from_bytes(*id), a.clone())),
        );

        let mut anchors = Vec::new();
        anchors
            .try_reserve_exact(state.anchors().len())
            .map_err(|_| crate::ArtifactError::Allocation)?;
        anchors.extend_from_slice(state.anchors());

        let mut committee = Vec::new();
        committee
            .try_reserve_exact(state.committee.len())
            .map_err(|_| crate::ArtifactError::Allocation)?;
        committee.extend(state.committee().cloned());

        Ok(Self {
            network: state.network(),
            note_anchor: state.note_anchor(),
            spent,
            accounts,
            anchors,
            policy: state.policy().clone(),
            committee_context: state.committee_context(),
            committee,
            pool: state.pool(),
            issued: state.issued(),
        })
    }
}
