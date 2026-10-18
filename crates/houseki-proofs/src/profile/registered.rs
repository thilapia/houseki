//! Family selection resolved from the compiled profile registry.

use super::{ExpectedIdentity, payment, reward_withdrawal};
use crate::StatementError;
use houseki_types::BodyCodecLimits;

/// Recognized proof family with immutable expected identity data.
#[derive(Debug)]
pub(crate) enum RegisteredProfile {
    /// Complete retained withdrawal relation and its fixed identity.
    RewardWithdrawal(ExpectedIdentity),

    /// Complete bounded payments with identity derived from actual public counts.
    Payment,
}

impl RegisteredProfile {
    /// Returns the selected family's representation bounds before body allocation.
    pub(crate) fn body_limits(&self) -> BodyCodecLimits {
        match self {
            Self::RewardWithdrawal(_) => reward_withdrawal::body_limits(),
            Self::Payment => payment::body_limits(),
        }
    }

    /// Borrows the retained withdrawal identity without using supplied proof metadata.
    pub(crate) const fn withdrawal_identity(&self) -> Result<&ExpectedIdentity, StatementError> {
        match self {
            Self::RewardWithdrawal(identity) => Ok(identity),
            Self::Payment => Err(StatementError::IdentityMismatch),
        }
    }
}
