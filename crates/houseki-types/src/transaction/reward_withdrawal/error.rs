//! Errors when constructing a [`RewardWithdrawalBody`](super::RewardWithdrawalBody).

use thiserror::Error;

/// Errors when constructing a [`RewardWithdrawalBody`](super::RewardWithdrawalBody).
#[derive(Debug, Error)]
pub enum RewardWithdrawalBodyError {
    /// The public withdrawal amount is zero.
    #[error("the public withdrawal amount must be greater than zero")]
    ZeroPublicAmount,
}
