//! Typed public statements retained independently of mutated proof bytes.

use houseki_proofs::{
    ProofContext, ProofRuntime, VerifyError, verify_payment, verify_reward_withdrawal,
};
use houseki_types::{
    EncodedTransactionProof, NoteTreeAnchor, PaymentBody, RewardWithdrawalBody, TransactionContext,
};

/// One trusted corpus statement with its independently retained expected anchor.
pub(crate) enum Body {
    /// A complete payment and its original count-bound application root.
    Payment {
        /// Immutable original canonical payment body.
        body: Box<PaymentBody>,

        /// Independently retained occupied count and root.
        anchor: NoteTreeAnchor,
    },

    /// A complete withdrawal body without a source authorization claim.
    Withdrawal(Box<RewardWithdrawalBody>),
}

impl Body {
    /// Returns the expected context from the trusted original fixture.
    pub(crate) fn context(&self) -> TransactionContext {
        match self {
            Self::Payment { body, .. } => body.context(),
            Self::Withdrawal(body) => body.context(),
        }
    }

    /// Runs the actual family verifier and checks the evidence's original body borrow.
    pub(crate) fn verify(
        &self,
        proof: &EncodedTransactionProof,
        context: &ProofContext,
        runtime: &ProofRuntime,
    ) -> Result<(), VerifyError> {
        match self {
            Self::Payment { body, anchor } => {
                let evidence = verify_payment(runtime, body, anchor, proof, context)?;
                assert!(std::ptr::eq(evidence.body(), body.as_ref()));
                assert!(std::ptr::eq(evidence.anchor(), anchor));
                assert!(std::ptr::eq(evidence.context(), context));
            }
            Self::Withdrawal(body) => {
                let evidence = verify_reward_withdrawal(runtime, body, proof, context)?;
                assert!(std::ptr::eq(evidence.body(), body.as_ref()));
                assert!(std::ptr::eq(evidence.context(), context));
            }
        }

        Ok(())
    }
}
