//! Errors from assembling a withdrawal encryption core.

use thiserror::Error;

/// A failure to construct typed reward withdrawal inputs for note encryption.
#[derive(Debug, Error)]
pub enum RewardWithdrawalEncryptionCoreError {
    /// The public withdrawal amount is zero.
    #[error("the public withdrawal amount must be greater than zero")]
    ZeroPublicAmount,
}
