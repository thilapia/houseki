//! Complete logical state independent of operational source progress.

use super::{AnchorRecord, StateError};
use crate::{CommitteeEntry, ExecutionPolicy};
use houseki_state::NoteTree;
use houseki_types::{
    Amount, CommitteeContext, NetworkId, NoteCommitment, NoteTreeAnchor, Nullifier, RewardAccount,
    RewardAccountId, ValidatorId,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Bounded native state validated as a representation before commitment authentication.
///
/// Read access alone establishes neither a trusted parent nor consensus finality.
pub struct LogicalState {
    /// Network bound into note and account derivation.
    pub(crate) network: NetworkId,

    /// Concrete tree derived from the complete ordered leaf list.
    pub(crate) tree: NoteTree,

    /// Ordered leaves retain repeated commitments as distinct instances.
    pub(crate) leaves: Vec<NoteCommitment>,

    /// Spent markers keyed by their complete bytes.
    pub(crate) spent: HashMap<[u8; 64], Nullifier>,

    /// Evolving account records keyed by complete account identity.
    pub(crate) accounts: HashMap<[u8; 64], RewardAccount>,

    /// Retained canonical history in checkpoint order.
    pub(crate) anchors: Vec<AnchorRecord>,

    /// Immutable execution policy reused across independent working states.
    pub(crate) policy: Arc<ExecutionPolicy>,

    /// Fixed epoch and committee identity.
    pub(crate) committee_context: CommitteeContext,

    /// Immutable fixture registrations and beneficiary mapping.
    pub(crate) committee: Arc<HashMap<[u8; 64], CommitteeEntry>>,

    /// Evolving aggregate shielded balance.
    pub(crate) pool: Amount,

    /// Fixed bounded supply declared at bootstrap.
    pub(crate) issued: Amount,
}

impl LogicalState {
    /// Returns the state network.
    pub const fn network(&self) -> NetworkId {
        self.network
    }

    /// Returns the concrete count bound note descriptor.
    pub fn note_anchor(&self) -> NoteTreeAnchor {
        self.tree.anchor()
    }

    /// Borrows original leaves in insertion order.
    pub fn leaves(&self) -> &[NoteCommitment] {
        &self.leaves
    }

    /// Borrows the distinct spent markers without assigning serialization order.
    pub fn spent(&self) -> impl Iterator<Item = &Nullifier> {
        self.spent.values()
    }

    /// Tests the complete public marker against the spent set.
    pub fn is_spent(&self, nullifier: Nullifier) -> bool {
        self.spent.contains_key(nullifier.as_bytes())
    }

    /// Looks up an account by complete identity.
    pub fn account(&self, id: RewardAccountId) -> Option<&RewardAccount> {
        self.accounts.get(id.as_bytes())
    }

    /// Borrows complete account records without assigning serialization order.
    pub fn accounts(&self) -> impl Iterator<Item = (&[u8; 64], &RewardAccount)> {
        self.accounts.iter()
    }

    /// Borrows retained checkpoint anchors in canonical sequence order.
    pub fn anchors(&self) -> &[AnchorRecord] {
        &self.anchors
    }

    /// Borrows the immutable committed policy representation.
    pub fn policy(&self) -> &ExecutionPolicy {
        &self.policy
    }

    /// Returns the fixed committee context.
    pub const fn committee_context(&self) -> CommitteeContext {
        self.committee_context
    }

    /// Borrows fixed validator registrations without assigning serialization order.
    pub fn committee(&self) -> impl Iterator<Item = &CommitteeEntry> {
        self.committee.values()
    }

    /// Resolves an authenticated author's registered fee beneficiary.
    pub fn beneficiary(&self, validator: ValidatorId) -> Option<RewardAccountId> {
        self.committee
            .get(validator.as_bytes())
            .map(CommitteeEntry::reward_account)
    }

    /// Returns the current shielded pool total.
    pub const fn pool(&self) -> Amount {
        self.pool
    }

    /// Returns the fixed issued supply.
    pub const fn issued(&self) -> Amount {
        self.issued
    }

    /// Checks full width accounting against the bounded bootstrap supply.
    ///
    /// # Errors
    ///
    /// Rejects overflow or any difference between pool plus account balances and issuance.
    pub fn validate_conservation(&self) -> Result<(), StateError> {
        let sum = self
            .accounts
            .values()
            .try_fold(self.pool.atoms(), |sum, a| {
                sum.checked_add(a.balance().atoms())
            })
            .ok_or(StateError::Conservation)?;
        if sum != self.issued.atoms() || sum > Amount::MAX_ATOMS {
            return Err(StateError::Conservation);
        }
        Ok(())
    }
}
