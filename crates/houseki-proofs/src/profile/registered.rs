//! Family selection resolved from the compiled profile registry.

use super::{ExpectedIdentity, reward_withdrawal};
use houseki_types::BodyCodecLimits;

/// Recognized proof family with immutable expected identity data.
#[derive(Debug)]
pub(crate) enum RegisteredProfile {
    /// Complete retained withdrawal relation and its fixed identity.
    RewardWithdrawal(ExpectedIdentity),
}

impl RegisteredProfile {
    /// Returns the selected family's representation bounds before body allocation.
    pub(crate) fn body_limits(&self) -> BodyCodecLimits {
        match self {
            Self::RewardWithdrawal(_) => reward_withdrawal::body_limits(),
        }
    }

    /// Borrows the retained withdrawal identity without using supplied proof metadata.
    pub(crate) const fn withdrawal_identity(&self) -> &ExpectedIdentity {
        match self {
            Self::RewardWithdrawal(identity) => identity,
        }
    }
}
