//! Native owners and public bodies used only by withdrawal tests.

use houseki_crypto::{CryptoSuite, MlKem1024DecapsulationKey};
use houseki_notes::{NoteBlinding, NoteFormat, NoteOpening, NoteRecipient};
use houseki_types::{
    AddressContext, AddressFormatVersion, Amount, CheckpointSequence, EncodedMlDsa87PublicKey,
    EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope, FeeScheduleId, NetworkId, NoteOutput,
    OwnershipCommitment, ProofProfileId, ProtocolVersion, RecipientDescriptor, RewardAccountId,
    RewardWithdrawalBody, TransactionContext, ValidityCheckpointRange, WithdrawalNonce,
};

/// Supplies valid native key bytes and an opaque envelope to keep relation scope explicit.
pub(super) fn withdrawal(atoms: u128, payload_bytes: usize) -> (NoteOpening, RewardWithdrawalBody) {
    let network = NetworkId::from_bytes([7; 64]);
    let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
    let recipient = NoteRecipient::validate(
        &RecipientDescriptor::new(
            AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
            OwnershipCommitment::from_bytes([12; 64]),
            key.encapsulation_key().to_encoded(),
        ),
        network,
    )
    .unwrap();
    let amount = Amount::from_atoms(atoms).unwrap();
    let opening = NoteOpening::new(
        NoteFormat::V1,
        &recipient,
        amount,
        NoteBlinding::generate().unwrap(),
    )
    .unwrap();
    let context = TransactionContext::new(
        network,
        ProtocolVersion::new(1),
        ProofProfileId::new(0xffff0007),
        FeeScheduleId::new(4),
        ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
            .unwrap(),
    );
    let output = NoteOutput::new(
        opening.commitment().unwrap(),
        EncryptedNoteEnvelope::new(
            EncodedMlKem1024Ciphertext::from_bytes([21; 1568]),
            vec![31; payload_bytes],
            payload_bytes,
        )
        .unwrap(),
    );
    let body = RewardWithdrawalBody::new(
        context,
        RewardAccountId::from_bytes([14; 64]),
        EncodedMlDsa87PublicKey::from_bytes([15; 2592]),
        WithdrawalNonce::new(u64::MAX),
        amount,
        Amount::from_atoms(17).unwrap(),
        output,
    )
    .unwrap();

    (opening, body)
}
