//! Fixed fixture validator metadata and fee beneficiary mapping.

use houseki_types::{RewardAccountId, ValidatorId};

/// Declared committee member validated when building a bootstrap candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeEntry {
    /// Complete immutable validator identity.
    validator: ValidatorId,

    /// Positive weight with a checked aggregate across the committee.
    weight: u128,

    /// Registered account receiving this author's accepted fees.
    reward_account: RewardAccountId,

    /// Bounded opaque consensus key metadata under fixture trust.
    key_descriptor: Vec<u8>,
}

impl CommitteeEntry {
    /// Retains declared metadata without authenticating a consensus key or
    /// registration.
    pub fn new(
        validator: ValidatorId,
        weight: u128,
        reward_account: RewardAccountId,
        key_descriptor: Vec<u8>,
    ) -> Self {
        Self {
            validator,
            weight,
            reward_account,
            key_descriptor,
        }
    }

    /// Returns the declared validator identity.
    pub const fn validator(&self) -> ValidatorId {
        self.validator
    }

    /// Returns the declared weight.
    pub const fn weight(&self) -> u128 {
        self.weight
    }

    /// Returns the account mapped to accepted fees.
    pub const fn reward_account(&self) -> RewardAccountId {
        self.reward_account
    }

    /// Borrows the complete opaque key metadata.
    pub fn key_descriptor(&self) -> &[u8] {
        &self.key_descriptor
    }
}
