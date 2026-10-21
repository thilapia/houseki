//! Synthetic withdrawal delivery using only the public native owner APIs.

use houseki_crypto::{
    CryptoSuite, MlDsa87SigningKey, MlKem1024DecapsulationKey, RewardWithdrawalEncryptionCore,
};
use houseki_notes::{
    NoteBlinding, NoteFormat, NoteOpening, NoteRecipient, encrypt_withdrawal_output,
    withdrawal_encryption_core,
};
use houseki_proofs::EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE;
use houseki_types::{
    AddressContext, AddressFormatVersion, Amount, CheckpointSequence, FeeScheduleId, NetworkId,
    OwnershipCommitment, ProtocolVersion, RecipientDescriptor, RewardWithdrawalBody,
    TransactionContext, ValidityCheckpointRange, WithdrawalNonce,
};
use std::error::Error;

/// Native private owners and a fully encrypted public body retained only for this example run.
pub(crate) struct Fixture {
    /// Complete canonical public transaction to be bound by both proof and signature.
    pub(crate) body: RewardWithdrawalBody,

    /// Borrowed by proving and destroyed before independent verification.
    pub(crate) opening: NoteOpening,

    /// Recipient context used for independent authenticated recovery.
    pub(crate) recipient: NoteRecipient,

    /// Original recipient decapsulation owner, never passed to the proof API.
    pub(crate) decryption: MlKem1024DecapsulationKey,

    /// Source authority owner, never passed to the proof API.
    pub(crate) authority: MlDsa87SigningKey,
}

impl Fixture {
    /// Creates fresh native private randomness and encrypts one synthetic ordinary output.
    pub(crate) fn new() -> Result<Self, Box<dyn Error>> {
        let network = NetworkId::from_bytes([7; 64]);
        let decryption = MlKem1024DecapsulationKey::generate()?;
        let authority = MlDsa87SigningKey::generate()?;
        let recipient = NoteRecipient::validate(
            &RecipientDescriptor::new(
                AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
                OwnershipCommitment::from_bytes([12; 64]),
                decryption.encapsulation_key().to_encoded(),
            ),
            network,
        )?;
        let amount = Amount::from_atoms(3)?;
        let opening = NoteOpening::new(
            NoteFormat::V1,
            &recipient,
            amount,
            NoteBlinding::generate()?,
        )?;
        let context = TransactionContext::new(
            network,
            ProtocolVersion::new(1),
            EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE,
            FeeScheduleId::new(0xffff0001),
            ValidityCheckpointRange::new(CheckpointSequence::new(0), CheckpointSequence::new(100))?,
        );
        let source = authority.verification_key().reward_account_id(network)?;
        let core = RewardWithdrawalEncryptionCore::new(
            context,
            source,
            authority.verification_key().to_encoded(),
            WithdrawalNonce::new(0),
            amount,
            Amount::from_atoms(1)?,
            (opening.commitment()?, CryptoSuite::V1),
        )?;
        let output = encrypt_withdrawal_output(&core, &recipient, &opening, 4096)?;
        let body = RewardWithdrawalBody::new(
            context,
            source,
            core.withdrawal_public_key().clone(),
            core.nonce(),
            amount,
            core.public_fee(),
            output,
        )?;
        let projected = withdrawal_encryption_core(&body, 4096)?;
        assert_eq!(projected, core);
        assert_eq!(projected.digest()?, core.digest()?);

        Ok(Self {
            body,
            opening,
            recipient,
            decryption,
            authority,
        })
    }
}
