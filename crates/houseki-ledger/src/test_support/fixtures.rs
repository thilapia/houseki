//! Representation fixtures contain no wallet witnesses or secret keys.

use crate::{AnchorRecord, BootstrapManifest, CommitteeEntry, ExecutionPolicy, SourceCursor};
use houseki_crypto::MlDsa87VerificationKey;
use houseki_state::NoteTree;
use houseki_types::{
    Amount, CheckpointSequence, CommitteeContext, CommitteeId, EncodedMlDsa87PublicKey, Epoch,
    NetworkId, NoteCommitment, RewardAccount, ValidatorId, WithdrawalNonce,
};

/// Builds a closed one-account fixture with one retained note leaf.
pub(crate) fn manifest() -> BootstrapManifest {
    let network = NetworkId::from_bytes([7; 64]);
    let authority = EncodedMlDsa87PublicKey::from_bytes([14; 2592]);
    let account_id = MlDsa87VerificationKey::from_encoded(&authority)
        .reward_account_id(network)
        .unwrap();
    let leaf = NoteCommitment::from_bytes([2; 64]);
    let mut tree = NoteTree::new(network).unwrap();
    tree.append(leaf).unwrap();
    BootstrapManifest {
        network,
        sequence: CheckpointSequence::new(0),
        parent_artifact_id: crate::ExecutionArtifactId::from_bytes([0; 64]),
        expected_state_commitment: crate::StateCommitment::from_bytes([9; 64]),
        expected_note_anchor: tree.anchor(),
        fixture_unit_ids: vec![],
        source_cursor: SourceCursor::Exhausted {
            stream_id: crate::FixtureStreamId::from_bytes([4; 64]),
        },
        leaves: vec![leaf],
        spent: vec![],
        accounts: vec![(
            account_id,
            RewardAccount::new(
                authority,
                Amount::from_atoms(0).unwrap(),
                WithdrawalNonce::new(0),
            ),
        )],
        anchors: vec![AnchorRecord::new(CheckpointSequence::new(0), tree.anchor())],
        policy: ExecutionPolicy::development().unwrap(),
        committee_context: CommitteeContext::new(Epoch::new(0), CommitteeId::from_bytes([3; 64])),
        committee: vec![CommitteeEntry::new(
            ValidatorId::from_bytes([5; 64]),
            1,
            account_id,
            vec![6],
        )],
        pool: Amount::from_atoms(100).unwrap(),
        issued: Amount::from_atoms(100).unwrap(),
    }
}

use houseki_types::{
    EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope, FeeScheduleId, NoteOutput, NoteRoot,
    Nullifier, PaymentBody, PaymentCountLimits, PaymentInputs, PaymentOutputs, ProofProfileId,
    ProtocolVersion, TransactionContext, ValidityCheckpointRange,
};

/// Builds an unverified declared payment for canonical record fixtures.
pub(crate) fn payment_body(inputs: usize, outputs: usize) -> PaymentBody {
    let limits = PaymentCountLimits::new(8, 8).unwrap();
    let context = TransactionContext::new(
        NetworkId::from_bytes([1; 64]),
        ProtocolVersion::new(1),
        ProofProfileId::new(0xffff0008),
        FeeScheduleId::new(0xffff0001),
        ValidityCheckpointRange::new(CheckpointSequence::new(0), CheckpointSequence::new(9))
            .unwrap(),
    );
    let nullifiers = (0..inputs)
        .map(|i| Nullifier::from_bytes([i as u8; 64]))
        .collect();
    let output = NoteOutput::new(
        NoteCommitment::from_bytes([2; 64]),
        EncryptedNoteEnvelope::new(EncodedMlKem1024Ciphertext::from_bytes([0; 1568]), vec![], 0)
            .unwrap(),
    );
    PaymentBody::new(
        context,
        PaymentInputs::new(NoteRoot::from_bytes([3; 64]), nullifiers, limits).unwrap(),
        PaymentOutputs::new(vec![output; outputs], limits).unwrap(),
        Amount::from_atoms(0).unwrap(),
        limits,
    )
    .unwrap()
}
