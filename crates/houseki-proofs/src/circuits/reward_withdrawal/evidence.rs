//! Body scoped evidence of the complete withdrawal output relation.

use crate::ProofContext;
use houseki_types::RewardWithdrawalBody;

/// Cryptographically checked output evidence borrowing the exact body and expected context.
///
/// This establishes a supported ordinary opening with the body's positive public amount and
/// commitment, bound to its complete canonical bytes including the opaque encrypted envelope.
///
/// Source authority, signature validity, nonce, balance, fee policy, delivery correctness and
/// checkpoint eligibility remain separate checks before execution.
///
/// Evidence retains neither the witness, proof storage nor the runtime's operation slot.
#[derive(Debug)]
#[must_use]
pub struct VerifiedRewardWithdrawal<'a> {
    /// Exact immutable body supplied to the successful verifier.
    pub(super) body: &'a RewardWithdrawalBody,

    /// Independently selected expected context supplied to that verification.
    pub(super) context: &'a ProofContext,
}

impl<'a> VerifiedRewardWithdrawal<'a> {
    /// Borrows the verified body without asserting that its account debit is authorized.
    pub const fn body(&self) -> &'a RewardWithdrawalBody {
        self.body
    }

    /// Borrows the expected context without asserting network activation or eligibility.
    pub const fn context(&self) -> &'a ProofContext {
        self.context
    }
}
