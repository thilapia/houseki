//! Declared reward withdrawals into a single private note.

mod error;

pub use error::RewardWithdrawalBodyError;

use super::{TransactionContext, TransactionKind};
use crate::{Amount, EncodedMlDsa87PublicKey, NoteOutput, RewardAccountId, WithdrawalNonce};

/// A reward withdrawal's declared source, public amounts and single note output.
///
/// Construction requires a positive public withdrawal amount.
///
/// The body carries exactly one ordinary note output and a separate mandatory public fee, with
/// its kind fixed to [`TransactionKind::RewardWithdrawal`].
///
/// The output proof must establish that the note contains the declared public amount, while the
/// ML-DSA-87 signature authorizes the source debit.
///
/// Neither is stored here.
///
/// Every [`Amount`] is representable as a fee.
///
/// Construction does not compute the gross debit or check affordability.
///
/// Execution must check the exact fee, compute amount plus fee with checked arithmetic and
/// require the source to cover that full debit even when it also receives the fee.
///
/// The including validator determines the fee beneficiary, which is not chosen by this body.
///
/// The declared key and account identifier are not authenticated by construction.
///
/// Consumers must check their binding and the account's immutable authority, match the nonce,
/// reject exhaustion and verify the complete body and context against the signature and expected
/// proof statement.
///
/// State changes must be atomic.
///
/// An exhausted nonce remains representable for execution to reject.
///
/// Consumers also enforce active byte and work limits, context support and note
/// recovery rules.
///
/// The V1 canonical codec preserves the complete body under explicit active limits.
///
/// Construction provides no signature transcript, transaction identifier derivation or
/// evidence of execution or finality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RewardWithdrawalBody {
    /// Declared network, rule identifiers and validity window.
    context: TransactionContext,

    /// Declared source reward account without an authenticated state claim.
    reward_account_id: RewardAccountId,

    /// Complete encoded source authority to be checked against account state.
    withdrawal_public_key: EncodedMlDsa87PublicKey,

    /// Declared source counter to be checked and advanced by execution.
    nonce: WithdrawalNonce,

    /// Positive public amount committed to the single ordinary output note.
    public_amount: Amount,

    /// Separate public fee included in the gross account debit.
    public_fee: Amount,

    /// Single declared ordinary note output for the withdrawn amount.
    output: NoteOutput,
}

impl RewardWithdrawalBody {
    /// Assembles a declared withdrawal with a positive public amount.
    ///
    /// # Errors
    ///
    /// Returns [`RewardWithdrawalBodyError::ZeroPublicAmount`] when the amount is zero,
    /// regardless of the fee.
    ///
    /// Other execution and authorization checks belong to consumers.
    pub fn new(
        context: TransactionContext,
        reward_account_id: RewardAccountId,
        withdrawal_public_key: EncodedMlDsa87PublicKey,
        nonce: WithdrawalNonce,
        public_amount: Amount,
        public_fee: Amount,
        output: NoteOutput,
    ) -> Result<Self, RewardWithdrawalBodyError> {
        if public_amount.atoms() == 0 {
            return Err(RewardWithdrawalBodyError::ZeroPublicAmount);
        }

        Ok(Self {
            context,
            reward_account_id,
            withdrawal_public_key,
            nonce,
            public_amount,
            public_fee,
            output,
        })
    }

    /// Returns the reward withdrawal operation kind implied by this body.
    pub const fn kind(&self) -> TransactionKind {
        TransactionKind::RewardWithdrawal
    }

    /// Returns the declared network, rule identifiers and validity window.
    pub const fn context(&self) -> TransactionContext {
        self.context
    }

    /// Returns the declared source reward account identifier.
    pub const fn reward_account_id(&self) -> RewardAccountId {
        self.reward_account_id
    }

    /// Borrows the declared withdrawal public key.
    pub const fn withdrawal_public_key(&self) -> &EncodedMlDsa87PublicKey {
        &self.withdrawal_public_key
    }

    /// Returns the declared withdrawal nonce without checking account state.
    pub const fn nonce(&self) -> WithdrawalNonce {
        self.nonce
    }

    /// Returns the positive public amount to be placed in the output note.
    pub const fn public_amount(&self) -> Amount {
        self.public_amount
    }

    /// Returns the declared public fee separately from the withdrawal amount.
    pub const fn public_fee(&self) -> Amount {
        self.public_fee
    }

    /// Borrows the single ordinary note output.
    pub const fn output(&self) -> &NoteOutput {
        &self.output
    }

    /// Consumes the body and returns its context, source, key, nonce, amounts and output.
    pub fn into_parts(
        self,
    ) -> (
        TransactionContext,
        RewardAccountId,
        EncodedMlDsa87PublicKey,
        WithdrawalNonce,
        Amount,
        Amount,
        NoteOutput,
    ) {
        (
            self.context,
            self.reward_account_id,
            self.withdrawal_public_key,
            self.nonce,
            self.public_amount,
            self.public_fee,
            self.output,
        )
    }
}

/// Construction, conversion and rejection properties of [`RewardWithdrawalBody`].
#[cfg(test)]
mod tests {
    use super::{RewardWithdrawalBody, RewardWithdrawalBodyError};
    use crate::{
        Amount, CheckpointSequence, EncodedMlDsa87PublicKey, EncodedMlKem1024Ciphertext,
        EncryptedNoteEnvelope, FeeScheduleId, NetworkId, NoteCommitment, NoteOutput,
        ProofProfileId, ProtocolVersion, RewardAccountId, TransactionContext, TransactionKind,
        ValidityCheckpointRange, WithdrawalNonce,
    };

    /// Builds a complete declared context for constructor boundary fixtures.
    fn context() -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([1; 64]),
            ProtocolVersion::new(2),
            ProofProfileId::new(3),
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        )
    }

    /// Builds one declared output with opaque envelope bytes for constructor fixtures.
    fn output() -> NoteOutput {
        NoteOutput::new(
            NoteCommitment::from_bytes([9; 64]),
            EncryptedNoteEnvelope::new(
                EncodedMlKem1024Ciphertext::from_bytes([10; 1568]),
                vec![11, 12, 13],
                3,
            )
            .unwrap(),
        )
    }

    /// Checks that zero withdrawal is rejected even when the fee is positive.
    #[test]
    fn zero_withdrawal_is_rejected_even_when_the_fee_is_positive() {
        for fee in [0, 1, Amount::MAX_ATOMS] {
            let result = RewardWithdrawalBody::new(
                context(),
                RewardAccountId::from_bytes([14; 64]),
                EncodedMlDsa87PublicKey::from_bytes([15; 2592]),
                WithdrawalNonce::new(16),
                Amount::from_atoms(0).unwrap(),
                Amount::from_atoms(fee).unwrap(),
                output(),
            );

            assert!(matches!(
                result,
                Err(RewardWithdrawalBodyError::ZeroPublicAmount)
            ));
        }
    }

    /// Checks that positive withdrawal preserves the complete declared body.
    #[test]
    fn positive_withdrawal_preserves_the_complete_declared_body() {
        let context = context();
        let account_id = RewardAccountId::from_bytes([14; 64]);
        let public_key = EncodedMlDsa87PublicKey::from_bytes([15; 2592]);
        let nonce = WithdrawalNonce::new(16);
        let amount = Amount::from_atoms(17).unwrap();
        let fee = Amount::from_atoms(18).unwrap();
        let output = output();
        let body = RewardWithdrawalBody::new(
            context,
            account_id,
            public_key.clone(),
            nonce,
            amount,
            fee,
            output.clone(),
        )
        .unwrap();

        assert_eq!(body.kind(), TransactionKind::RewardWithdrawal);
        assert_eq!(body.context(), context);
        assert_eq!(body.reward_account_id(), account_id);
        assert_eq!(body.withdrawal_public_key(), &public_key);
        assert_eq!(body.nonce(), nonce);
        assert_eq!(body.public_amount(), amount);
        assert_eq!(body.public_fee(), fee);
        assert_eq!(body.output(), &output);
        assert_eq!(
            body.into_parts(),
            (context, account_id, public_key, nonce, amount, fee, output)
        );
    }

    /// Checks that positive boundaries leave gross debit and nonce checks to execution.
    #[test]
    fn positive_boundaries_leave_gross_debit_and_nonce_checks_to_execution() {
        for (amount, fee) in [(1, 0), (Amount::MAX_ATOMS, 0), (1, Amount::MAX_ATOMS)] {
            let body = RewardWithdrawalBody::new(
                context(),
                RewardAccountId::from_bytes([0; 64]),
                EncodedMlDsa87PublicKey::from_bytes([0; 2592]),
                WithdrawalNonce::new(u64::MAX),
                Amount::from_atoms(amount).unwrap(),
                Amount::from_atoms(fee).unwrap(),
                output(),
            )
            .unwrap();

            assert_eq!(body.public_amount().atoms(), amount);
            assert_eq!(body.public_fee().atoms(), fee);
            assert_eq!(body.nonce().checked_next(), None);
        }
    }
}
