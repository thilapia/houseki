//! Immutable inputs for one output's later authenticated encryption.

mod associated_data;
mod error;

pub use error::NoteEncryptionContextError;

use houseki_types::{NoteCommitment, TransactionContext};

use super::{CryptoSuite, PaymentEncryptionCore, RewardWithdrawalEncryptionCore};
use crate::MlKem1024EncapsulationKey;

/// Prepared public inputs for encrypting or recovering one note output.
///
/// Construction selects the commitment and suite from a typed core and
/// derives its complete digest internally. It retains an owned clone of the
/// validated recipient public key. It accepts no supplied core digest,
/// recipient-binding hash or independently chosen output fields.
///
/// The context is an immutable snapshot. Rebuilding or discarding the source
/// core or key does not alter it. A changed intended body requires a new
/// context. Final body assembly must preserve the core fields and output order
/// and match each payload's suite to its corresponding output.
///
/// Construction prepares inputs only. [`Self::associated_data`] derives the
/// Poseidon2 recipient binding internally and frames it with the selected
/// output, core digest, encapsulation and nonce. Encapsulation, key derivation
/// and authenticated encryption are separate operations.
/// The recipient key is not included in the core digest itself.
///
/// Construction does not establish recipient identity, agreement with a note
/// opening, active protocol rules or transaction validity. Recovery must
/// reconstruct the core from the completed body and resolve its payload
/// suites. Successful context construction is not authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteEncryptionContext {
    transaction_context: TransactionContext,
    core_digest: [u8; 64],
    output_index: u64,
    note_commitment: NoteCommitment,
    suite: CryptoSuite,
    recipient_key: MlKem1024EncapsulationKey,
}

impl NoteEncryptionContext {
    /// Prepares the payment output at the supplied zero based index.
    ///
    /// Selects its commitment and suite from the actual core before deriving
    /// the digest. Hashing traverses the complete core for each successful
    /// construction. Only the selected fields and public key are retained.
    ///
    /// # Errors
    ///
    /// Rejects a missing output with
    /// [`NoteEncryptionContextError::OutputIndexOutOfBounds`] before hashing,
    /// including an index that cannot be represented by the host indexing
    /// type. Otherwise propagates framing errors as
    /// [`NoteEncryptionContextError::CoreDigest`].
    pub fn for_payment(
        core: &PaymentEncryptionCore,
        output_index: u64,
        recipient_key: &MlKem1024EncapsulationKey,
    ) -> Result<Self, NoteEncryptionContextError> {
        let output = usize::try_from(output_index)
            .ok()
            .and_then(|index| core.outputs().get(index))
            .copied()
            .ok_or(NoteEncryptionContextError::OutputIndexOutOfBounds {
                index: output_index,
                output_count: core.outputs().len(),
            })?;

        Ok(Self::from_derived_core(
            core.context(),
            core.digest()?,
            output_index,
            output,
            recipient_key,
        ))
    }

    /// Prepares the withdrawal's sole output at index zero.
    ///
    /// The recipient KEM key is separate from the declared withdrawal
    /// authority key already bound by the core digest.
    ///
    /// # Errors
    ///
    /// Propagates core framing errors as
    /// [`NoteEncryptionContextError::CoreDigest`].
    pub fn for_reward_withdrawal(
        core: &RewardWithdrawalEncryptionCore,
        recipient_key: &MlKem1024EncapsulationKey,
    ) -> Result<Self, NoteEncryptionContextError> {
        Ok(Self::from_derived_core(
            core.context(),
            core.digest()?,
            0,
            core.output(),
            recipient_key,
        ))
    }

    /// Returns the complete declared context bound by the core digest.
    pub const fn transaction_context(&self) -> TransactionContext {
        self.transaction_context
    }

    /// Borrows the internally derived digest of the complete typed core.
    ///
    /// This digest does not include the recipient KEM key, encapsulation or
    /// nonce and is not by itself the final associated data.
    pub const fn core_digest(&self) -> &[u8; 64] {
        &self.core_digest
    }

    /// Returns the selected output's zero based position in the core.
    pub const fn output_index(&self) -> u64 {
        self.output_index
    }

    /// Returns the commitment taken from the selected core output.
    pub const fn note_commitment(&self) -> NoteCommitment {
        self.note_commitment
    }

    /// Returns the recognized suite taken from the selected core output.
    pub const fn suite(&self) -> CryptoSuite {
        self.suite
    }

    /// Borrows the validated recipient key retained for later suite operations.
    pub const fn recipient_key(&self) -> &MlKem1024EncapsulationKey {
        &self.recipient_key
    }

    /// Assembles only inputs already selected and derived by the constructors.
    fn from_derived_core(
        transaction_context: TransactionContext,
        core_digest: [u8; 64],
        output_index: u64,
        output: (NoteCommitment, CryptoSuite),
        recipient_key: &MlKem1024EncapsulationKey,
    ) -> Self {
        let (note_commitment, suite) = output;
        // Keep suite handling exhaustive so a future algorithm assignment
        // must explicitly address compatibility with this validated key type.
        let recipient_key = match suite {
            CryptoSuite::V1 => recipient_key.clone(),
        };
        Self {
            transaction_context,
            core_digest,
            output_index,
            note_commitment,
            suite,
            recipient_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use houseki_types::{
        Amount, CheckpointSequence, EncodedMlDsa87PublicKey, EncodedMlKem1024PublicKey,
        FeeScheduleId, NetworkId, NoteRoot, Nullifier, PaymentCountLimits, PaymentInputs,
        ProofProfileId, ProtocolVersion, RewardAccountId, ValidityCheckpointRange, WithdrawalNonce,
    };

    use super::{
        CryptoSuite, MlKem1024EncapsulationKey, NoteCommitment, NoteEncryptionContext,
        NoteEncryptionContextError, PaymentEncryptionCore, RewardWithdrawalEncryptionCore,
        TransactionContext,
    };

    // Independently assembled using the specified Houseki core layouts,
    // Python int.to_bytes(n, "little") and hashlib.sha3_512. Recipient keys
    // are absent from these preimages and are retained separately below.
    const PAYMENT_DIGEST: &str = concat!(
        "f1d90173ffac8411e9ba423d5caa7fb9296367609b1b3f9f7c3b6ad41804fc10",
        "c6d259c5ec4e8c94ed2fcf311330eec8827d4727eb9bf5fdfa22b146b7c3c220"
    );
    const WITHDRAWAL_DIGEST: &str = concat!(
        "5a52be6970c5341cd0591dfc88e3a8415a395b879b4ea3ad0a75d0180f66122d1",
        "45be827421fdac9e7c3e1da770e60a2712f420fc2aa6d0703a8f3dd9e17e644"
    );

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn transaction_context() -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([1; 64]),
            ProtocolVersion::new(2),
            ProofProfileId::new(3),
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        )
    }

    fn limits() -> PaymentCountLimits {
        PaymentCountLimits::new(2, 3).unwrap()
    }

    fn payment() -> PaymentEncryptionCore {
        PaymentEncryptionCore::new(
            transaction_context(),
            PaymentInputs::new(
                NoteRoot::from_bytes([9; 64]),
                [10, 11]
                    .map(|byte| Nullifier::from_bytes([byte; 64]))
                    .to_vec(),
                limits(),
            )
            .unwrap(),
            [12, 13, 12]
                .map(|byte| (NoteCommitment::from_bytes([byte; 64]), CryptoSuite::V1))
                .to_vec(),
            Amount::from_atoms(17).unwrap(),
            limits(),
        )
        .unwrap()
    }

    fn withdrawal() -> RewardWithdrawalEncryptionCore {
        RewardWithdrawalEncryptionCore::new(
            transaction_context(),
            RewardAccountId::from_bytes([14; 64]),
            EncodedMlDsa87PublicKey::from_bytes([15; 2592]),
            WithdrawalNonce::new(16),
            Amount::from_atoms(17).unwrap(),
            Amount::from_atoms(18).unwrap(),
            (NoteCommitment::from_bytes([19; 64]), CryptoSuite::V1),
        )
        .unwrap()
    }

    fn recipient_key(seed_byte: u8) -> MlKem1024EncapsulationKey {
        // Canonical zero coefficients with unrestricted public seed bytes.
        // This fixture asserts encoding validation, not honest key generation.
        let mut bytes = [0; 1568];
        bytes[1536..].fill(seed_byte);
        MlKem1024EncapsulationKey::try_from(&EncodedMlKem1024PublicKey::from_bytes(bytes)).unwrap()
    }

    #[test]
    fn payment_selects_actual_outputs_and_distinguishes_duplicate_positions() {
        let core = payment();
        let key = recipient_key(20);
        let contexts: Vec<_> = [12, 13, 12]
            .into_iter()
            .enumerate()
            .map(|(index, byte)| {
                let index = u64::try_from(index).unwrap();
                let context = NoteEncryptionContext::for_payment(&core, index, &key).unwrap();
                assert_eq!(context.transaction_context(), transaction_context());
                assert_eq!(hex(context.core_digest()), PAYMENT_DIGEST);
                assert_eq!(context.output_index(), index);
                assert_eq!(
                    context.note_commitment(),
                    NoteCommitment::from_bytes([byte; 64])
                );
                assert_eq!(context.suite(), CryptoSuite::V1);
                assert_eq!(context.recipient_key().to_encoded(), key.to_encoded());
                context
            })
            .collect();

        assert_eq!(contexts[0].note_commitment(), contexts[2].note_commitment());
        assert_eq!(contexts[0].core_digest(), contexts[2].core_digest());
        assert_ne!(contexts[0], contexts[2]);
    }

    #[test]
    fn invalid_payment_indices_preserve_all_supplied_bits() {
        let core = payment();
        let key = recipient_key(20);
        for index in [3, 4, 256, 65_536, 1 << 32, u64::MAX] {
            assert!(matches!(
                NoteEncryptionContext::for_payment(&core, index, &key),
                Err(NoteEncryptionContextError::OutputIndexOutOfBounds {
                    index: supplied,
                    output_count: 3,
                }) if supplied == index
            ));
        }
    }

    #[test]
    fn withdrawal_selects_its_only_output_and_separate_recipient_key() {
        let context = {
            let core = withdrawal();
            let key = recipient_key(21);
            NoteEncryptionContext::for_reward_withdrawal(&core, &key).unwrap()
        };
        assert_eq!(context.transaction_context(), transaction_context());
        assert_eq!(hex(context.core_digest()), WITHDRAWAL_DIGEST);
        assert_eq!(context.output_index(), 0);
        assert_eq!(
            context.note_commitment(),
            NoteCommitment::from_bytes([19; 64])
        );
        assert_eq!(context.suite(), CryptoSuite::V1);
        assert_eq!(
            context.recipient_key().to_encoded(),
            recipient_key(21).to_encoded()
        );
    }

    #[test]
    fn rebuilding_a_payment_binds_unselected_fields_without_changing_the_old_context() {
        let key = recipient_key(20);
        let original = {
            let core = payment();
            NoteEncryptionContext::for_payment(&core, 0, &key).unwrap()
        };
        for change in 0..2 {
            let (context, inputs, mut outputs, mut fee) = payment().into_parts();
            if change == 0 {
                fee = Amount::from_atoms(18).unwrap();
            } else {
                outputs[1].0 = NoteCommitment::from_bytes([22; 64]);
            }
            let changed_core =
                PaymentEncryptionCore::new(context, inputs, outputs, fee, limits()).unwrap();
            let changed = NoteEncryptionContext::for_payment(&changed_core, 0, &key).unwrap();
            assert_eq!(changed.note_commitment(), original.note_commitment());
            assert_eq!(
                changed.transaction_context(),
                original.transaction_context()
            );
            assert_ne!(changed.core_digest(), original.core_digest());
            assert_eq!(hex(original.core_digest()), PAYMENT_DIGEST);
        }
    }

    #[test]
    fn rebuilding_a_withdrawal_recomputes_the_complete_core_digest() {
        let core = withdrawal();
        let key = recipient_key(21);
        let original = NoteEncryptionContext::for_reward_withdrawal(&core, &key).unwrap();
        let (context, account, authority, _, amount, fee, output) = core.into_parts();
        let changed_core = RewardWithdrawalEncryptionCore::new(
            context,
            account,
            authority,
            WithdrawalNonce::new(17),
            amount,
            fee,
            output,
        )
        .unwrap();
        let changed = NoteEncryptionContext::for_reward_withdrawal(&changed_core, &key).unwrap();
        assert_eq!(changed.note_commitment(), original.note_commitment());
        assert_eq!(
            changed.transaction_context(),
            original.transaction_context()
        );
        assert_ne!(changed.core_digest(), original.core_digest());
        assert_eq!(hex(original.core_digest()), WITHDRAWAL_DIGEST);
    }

    #[test]
    fn recipient_keys_remain_distinct_inputs_outside_the_core_digest() {
        let payment = payment();
        let withdrawal = withdrawal();
        let first_key = recipient_key(20);
        let second_key = recipient_key(21);
        let pairs = [
            (
                NoteEncryptionContext::for_payment(&payment, 0, &first_key).unwrap(),
                NoteEncryptionContext::for_payment(&payment, 0, &second_key).unwrap(),
            ),
            (
                NoteEncryptionContext::for_reward_withdrawal(&withdrawal, &first_key).unwrap(),
                NoteEncryptionContext::for_reward_withdrawal(&withdrawal, &second_key).unwrap(),
            ),
        ];
        for (first, second) in pairs {
            assert_eq!(first.core_digest(), second.core_digest());
            assert_eq!(first.note_commitment(), second.note_commitment());
            assert_eq!(first.recipient_key().to_encoded(), first_key.to_encoded());
            assert_eq!(second.recipient_key().to_encoded(), second_key.to_encoded());
            assert_ne!(first, second);
        }
    }
}
