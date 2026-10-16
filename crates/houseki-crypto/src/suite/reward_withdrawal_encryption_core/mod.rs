//! Typed reward withdrawal inputs available before note encryption.

mod error;

pub use error::RewardWithdrawalEncryptionCoreError;

use houseki_types::{
    Amount, EncodedMlDsa87PublicKey, NoteCommitment, RewardAccountId, TransactionContext,
    TransactionKind, WithdrawalNonce,
};

use super::CryptoSuite;

/// A reward withdrawal's declared fields available before its output is encrypted.
///
/// The single output is a note commitment followed by its recognized
/// cryptographic suite. Construction requires a positive public withdrawal
/// amount and preserves the public fee separately. It contains no encrypted
/// envelope, recipient KEM key, plaintext opening, proof, signature or supplied
/// encryption core digest.
///
/// The account identifier and encoded withdrawal authority key are declared
/// inputs. Construction does not validate that key or its account binding,
/// establish authority, match the nonce to state or check affordability.
/// Every [`Amount`] is representable as a fee, and an exhausted nonce remains
/// representable. Consumers must check the active rules, exact fee, nonce and
/// gross debit with checked arithmetic before authorizing a withdrawal.
///
/// Borrowing exposes no mutable fields. [`Self::digest`] derives a native
/// encryption core digest from these typed fields. It does not construct a
/// per-output encryption context. Final body assembly
/// must preserve these fields and match the encrypted payload's suite to the
/// output entry. Note recovery and proof validation remain separate checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RewardWithdrawalEncryptionCore {
    context: TransactionContext,
    reward_account_id: RewardAccountId,
    withdrawal_public_key: EncodedMlDsa87PublicKey,
    nonce: WithdrawalNonce,
    public_amount: Amount,
    public_fee: Amount,
    output: (NoteCommitment, CryptoSuite),
}

impl RewardWithdrawalEncryptionCore {
    /// Assembles typed withdrawal inputs without requiring an encrypted output.
    ///
    /// # Errors
    ///
    /// Returns [`RewardWithdrawalEncryptionCoreError::ZeroPublicAmount`] when
    /// the withdrawal amount is zero, regardless of the fee. No other authority
    /// or execution checks are performed here.
    pub fn new(
        context: TransactionContext,
        reward_account_id: RewardAccountId,
        withdrawal_public_key: EncodedMlDsa87PublicKey,
        nonce: WithdrawalNonce,
        public_amount: Amount,
        public_fee: Amount,
        output: (NoteCommitment, CryptoSuite),
    ) -> Result<Self, RewardWithdrawalEncryptionCoreError> {
        if public_amount.atoms() == 0 {
            return Err(RewardWithdrawalEncryptionCoreError::ZeroPublicAmount);
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

    /// Returns the reward withdrawal kind implied by this core.
    pub const fn kind(&self) -> TransactionKind {
        TransactionKind::RewardWithdrawal
    }

    /// Returns the complete declared transaction context.
    pub const fn context(&self) -> TransactionContext {
        self.context
    }

    /// Returns the declared source reward account identifier.
    pub const fn reward_account_id(&self) -> RewardAccountId {
        self.reward_account_id
    }

    /// Borrows the encoded withdrawal authority key without validating it.
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

    /// Returns the single note commitment and its recognized suite.
    pub const fn output(&self) -> (NoteCommitment, CryptoSuite) {
        self.output
    }

    /// Consumes the core and returns its fields for later body assembly.
    pub fn into_parts(
        self,
    ) -> (
        TransactionContext,
        RewardAccountId,
        EncodedMlDsa87PublicKey,
        WithdrawalNonce,
        Amount,
        Amount,
        (NoteCommitment, CryptoSuite),
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

#[cfg(test)]
mod tests {
    use houseki_types::{
        CheckpointSequence, FeeScheduleId, NetworkId, ProofProfileId, ProtocolVersion,
        ValidityCheckpointRange,
    };

    use super::{
        Amount, CryptoSuite, EncodedMlDsa87PublicKey, NoteCommitment, RewardAccountId,
        RewardWithdrawalEncryptionCore, RewardWithdrawalEncryptionCoreError, TransactionContext,
        TransactionKind, WithdrawalNonce,
    };

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

    fn output() -> (NoteCommitment, CryptoSuite) {
        (NoteCommitment::from_bytes([9; 64]), CryptoSuite::V1)
    }

    #[test]
    fn zero_withdrawal_is_rejected_regardless_of_the_fee() {
        for fee in [0, 1, Amount::MAX_ATOMS] {
            let result = RewardWithdrawalEncryptionCore::new(
                context(),
                RewardAccountId::from_bytes([10; 64]),
                EncodedMlDsa87PublicKey::from_bytes([11; 2592]),
                WithdrawalNonce::new(12),
                Amount::from_atoms(0).unwrap(),
                Amount::from_atoms(fee).unwrap(),
                output(),
            );

            assert!(matches!(
                result,
                Err(RewardWithdrawalEncryptionCoreError::ZeroPublicAmount)
            ));
        }
    }

    #[test]
    fn positive_withdrawal_preserves_the_complete_core_and_separate_fee() {
        let context = context();
        let account = RewardAccountId::from_bytes([13; 64]);
        let key = EncodedMlDsa87PublicKey::from_bytes(std::array::from_fn(|i| (i % 251) as u8));
        let nonce = WithdrawalNonce::new(14);
        let amount = Amount::from_atoms(15).unwrap();
        let fee = Amount::from_atoms(16).unwrap();
        let output = output();
        let core = RewardWithdrawalEncryptionCore::new(
            context,
            account,
            key.clone(),
            nonce,
            amount,
            fee,
            output,
        )
        .unwrap();

        assert_eq!(core.kind(), TransactionKind::RewardWithdrawal);
        assert_eq!(core.context(), context);
        assert_eq!(core.reward_account_id(), account);
        assert_eq!(core.withdrawal_public_key(), &key);
        assert_eq!(core.nonce(), nonce);
        assert_eq!(core.public_amount(), amount);
        assert_eq!(core.public_fee(), fee);
        assert_eq!(core.output(), output);
        assert_eq!(
            core.into_parts(),
            (context, account, key, nonce, amount, fee, output)
        );
    }

    #[test]
    fn positive_boundaries_leave_key_nonce_and_gross_debit_checks_to_consumers() {
        for (amount, fee) in [
            (1, 0),
            (Amount::MAX_ATOMS, 0),
            (1, Amount::MAX_ATOMS),
            (Amount::MAX_ATOMS, Amount::MAX_ATOMS),
        ] {
            let key = EncodedMlDsa87PublicKey::from_bytes([u8::MAX; 2592]);
            let core = RewardWithdrawalEncryptionCore::new(
                context(),
                RewardAccountId::from_bytes([0; 64]),
                key.clone(),
                WithdrawalNonce::new(u64::MAX),
                Amount::from_atoms(amount).unwrap(),
                Amount::from_atoms(fee).unwrap(),
                output(),
            )
            .unwrap();

            assert_eq!(core.withdrawal_public_key(), &key);
            assert_eq!(core.public_amount().atoms(), amount);
            assert_eq!(core.public_fee().atoms(), fee);
            assert_eq!(core.nonce().checked_next(), None);
            assert_eq!(core.output(), output());
        }
    }
}
