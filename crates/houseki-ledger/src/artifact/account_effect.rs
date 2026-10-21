//! Public representation of the canonical account effect record.

use houseki_types::{Amount, RewardAccountId, WithdrawalNonce};

/// Unverified account effect fields with no publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEffect {
    /// Changed account identity.
    pub account_id: RewardAccountId,

    /// Balance before the occurrence.
    pub before_balance: Amount,

    /// Nonce before the occurrence.
    pub before_nonce: WithdrawalNonce,

    /// Balance after the occurrence.
    pub after_balance: Amount,

    /// Nonce after the occurrence.
    pub after_nonce: WithdrawalNonce,
}
