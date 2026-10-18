//! Independent withdrawal verification from canonical public inputs and a bounded proof.

use super::VerifiedRewardWithdrawal;
use crate::{ProofContext, ProofRuntime, VerifyError, backend, statement::Statement};
use houseki_types::{EncodedTransactionProof, RewardWithdrawalBody};

/// Verifies the complete output relation without a witness or proving entropy.
///
/// The caller selects expected active rules independently and separately checks account authority,
/// signatures, nonce, balance, fees and checkpoint eligibility before applying a debit.
///
/// # Errors
///
/// Checks runtime admission before exact context and bounded body encoding, then validates the
/// proof byte cap, complete identity and canonical dimensions before cryptographic verification.
pub fn verify_reward_withdrawal<'a>(
    runtime: &ProofRuntime,
    body: &'a RewardWithdrawalBody,
    proof: &EncodedTransactionProof,
    context: &'a ProofContext,
) -> Result<VerifiedRewardWithdrawal<'a>, VerifyError> {
    let admission = runtime.acquire().map_err(|_| VerifyError::Busy)?;
    let statement =
        Statement::withdrawal(body, context.expected(), context.withdrawal_identity()?)?;
    backend::verify_withdrawal(
        &admission,
        &statement,
        context.withdrawal_identity()?,
        proof,
    )?;

    Ok(VerifiedRewardWithdrawal { body, context })
}
