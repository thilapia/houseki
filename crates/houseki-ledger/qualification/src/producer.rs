//! Fresh signed withdrawal production retaining public verification prerequisites only.

use crate::owner::Fixture;
use houseki_ledger::{
    AnchorRecord, BootstrapManifest, CommitteeEntry, ExecutionArtifactId, ExecutionPolicy,
    FixtureStreamId, FixtureStreamRecord, FixtureUnitId, FixtureUnitRecord, SnapshotRecord,
    SourceCursor, StateCommitment, encode_fixture_stream, encode_fixture_unit, encode_snapshot,
};
use houseki_proofs::{
    CancellationToken, ProofContext, ProofRuntime, prove_reward_withdrawal,
    verify_reward_withdrawal,
};
use houseki_state::NoteTree;
use houseki_types::{
    Amount, CheckpointSequence, CommitteeContext, CommitteeId, Epoch, Occurrence, RewardAccount,
    RewardWithdrawalEnvelope, ValidatorId, VertexId, WithdrawalNonce,
};
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::Instant,
};

/// Generates one actual proof and required source signature with no retained private inputs.
pub fn seed(directory: &Path) -> Result<(), Box<dyn Error>> {
    if directory.exists() {
        return Err("seed destination already exists".into());
    }
    let fixture = Fixture::new()?;
    let context = ProofContext::new(fixture.body.context())?;
    let signature = fixture
        .authority
        .sign_reward_withdrawal(&fixture.body, context.body_limits())?;
    let start = Instant::now();
    let proof = prove_reward_withdrawal(
        &ProofRuntime::new(),
        &fixture.body,
        &fixture.opening,
        &context,
        &CancellationToken::new(),
    )?;
    let _verified =
        verify_reward_withdrawal(&ProofRuntime::new(), &fixture.body, &proof, &context)?;
    fixture
        .authority
        .verification_key()
        .verify_reward_withdrawal(&fixture.body, &signature, context.body_limits())?;
    let recovered = houseki_notes::recover_withdrawal_output(
        &fixture.body,
        &fixture.recipient,
        &fixture.decryption,
        4096,
    )?;
    assert_eq!(recovered.amount(), &fixture.body.public_amount());
    drop(recovered);
    let network = fixture.body.context().network_id();
    let tree = NoteTree::new(network)?;
    let committee = CommitteeContext::new(Epoch::new(0), CommitteeId::from_bytes([3; 64]));
    let occurrence = Occurrence::new(
        VertexId::from_bytes([11; 64]),
        ValidatorId::from_bytes([5; 64]),
        committee,
        0,
        RewardWithdrawalEnvelope::new(fixture.body.clone(), proof.clone(), signature.clone())
            .into(),
    );
    let unit = encode_fixture_unit(&FixtureUnitRecord {
        ordinal: 0,
        previous_unit_id: FixtureUnitId::from_bytes([0; 64]),
        occurrences: vec![occurrence],
    })?;
    let unit_id = FixtureUnitId::from_bytes(houseki_crypto::ledger_fixture_order_unit(&unit)?);
    let stream = FixtureStreamId::from_bytes(houseki_crypto::ledger_fixture_order_stream(
        &encode_fixture_stream(&FixtureStreamRecord {
            network,
            starting_artifact_id: ExecutionArtifactId::from_bytes([0; 64]),
            unit_ids: vec![unit_id],
        })?,
    )?);
    let mut manifest = BootstrapManifest {
        network,
        sequence: CheckpointSequence::new(0),
        parent_artifact_id: ExecutionArtifactId::from_bytes([0; 64]),
        expected_state_commitment: StateCommitment::from_bytes([0; 64]),
        expected_note_anchor: tree.anchor(),
        fixture_unit_ids: vec![unit_id],
        source_cursor: SourceCursor::Unit {
            stream_id: stream,
            ordinal: 0,
            unit_id,
            offset: 0,
        },
        leaves: vec![],
        spent: vec![],
        accounts: vec![(
            fixture.body.reward_account_id(),
            RewardAccount::new(
                fixture.body.withdrawal_public_key().clone(),
                Amount::from_atoms(100)?,
                WithdrawalNonce::new(0),
            ),
        )],
        anchors: vec![AnchorRecord::new(CheckpointSequence::new(0), tree.anchor())],
        policy: ExecutionPolicy::development()?,
        committee_context: committee,
        committee: vec![CommitteeEntry::new(
            ValidatorId::from_bytes([5; 64]),
            1,
            fixture.body.reward_account_id(),
            vec![6],
        )],
        pool: Amount::from_atoms(0)?,
        issued: Amount::from_atoms(100)?,
    };
    let state = encode_snapshot(&SnapshotRecord::from_state(
        manifest.clone().candidate()?.state(),
    )?)?;
    manifest.expected_state_commitment =
        StateCommitment::from_bytes(houseki_crypto::ledger_reference_state(&state)?);
    let body = fixture.body.to_bytes(context.body_limits())?;
    let root = hex(manifest.expected_state_commitment.as_bytes());
    let stream_hex = hex(stream.as_bytes());
    fs::create_dir_all(directory)?;
    for (name, bytes) in [
        ("body.bin", body.as_slice()),
        ("proof.bin", proof.as_bytes()),
        ("signature.bin", signature.as_bytes()),
        ("unit.bin", unit.as_slice()),
        ("bootstrap-state.bin", state.as_slice()),
        ("bootstrap-state.hex", root.as_bytes()),
        ("stream.hex", stream_hex.as_bytes()),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))?;
        file.write_all(bytes)?;
    }
    println!(
        "public signed withdrawal seed generated: proof_bytes={}, elapsed_ms={}",
        proof.byte_len(),
        start.elapsed().as_millis()
    );
    Ok(())
}

/// Formats only complete public commitments for fixture metadata.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
