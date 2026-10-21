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

/// Generates one actual proof and required source signature with no retained private
/// inputs.
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

/// Generates a complete public corpus without exporting private fixture owners.
pub fn generate(
    workload: crate::Workload,
    directory: &Path,
) -> Result<crate::PublicFixture, crate::QualificationError> {
    if directory.exists() {
        return Err(crate::QualificationError::Input(
            "fixture destination already exists",
        ));
    }

    generate_inner(workload, directory).map_err(crate::QualificationError::Native)
}

/// Dispatches fresh proving and public native execution before writing a new corpus.
fn generate_inner(
    workload: crate::Workload,
    directory: &Path,
) -> Result<crate::PublicFixture, Box<dyn Error>> {
    let mut fixture = match workload {
        crate::Workload::ValueLoop
        | crate::Workload::FailedEarlyCopy
        | crate::Workload::SharedBeneficiary => crate::loop_fixture::build(workload)?,
        crate::Workload::Withdrawal => withdrawal_workload()?,
        _ => payment_workload(workload)?,
    };

    workload.validate_checkpoints(&fixture.checkpoints)?;
    fixture.directory = directory.to_path_buf();
    fixture.write(workload)?;
    Ok(fixture)
}

/// Proves one complete payment through the protected native owner API and records only
/// duration.
pub(crate) fn prove_payment_body(
    body: &houseki_types::PaymentBody,
    anchor: &houseki_types::NoteTreeAnchor,
    spends: &[houseki_notes::SpendWitness<'_>],
    outputs: &[&houseki_notes::NoteOpening],
    measurement: &mut crate::Measurement,
) -> Result<houseki_types::EncodedTransactionProof, Box<dyn Error>> {
    let context = ProofContext::new(body.context())?;
    let witness = houseki_proofs::PaymentWitness::new(spends, outputs)?;
    let started = Instant::now();
    let proof = houseki_proofs::prove_payment(
        &ProofRuntime::new(),
        body,
        anchor,
        &witness,
        &context,
        &CancellationToken::new(),
    )?;
    measurement.proving += started.elapsed();
    Ok(proof)
}

/// Builds actual family, repeated output, conflict and historical anchor payment workloads.
fn payment_workload(workload: crate::Workload) -> Result<crate::PublicFixture, Box<dyn Error>> {
    use crate::{
        Measurement, Workload,
        execution::{bootstrap, occurrence, run},
        payment_fixture::Fixture as PaymentFixture,
    };
    use houseki_crypto::MlDsa87SigningKey;
    use houseki_ledger::{DecodeLimits, ExecutionPolicy, OutputBody, decode_policy, encode_policy};
    use houseki_types::{ExecutionOutcome, ExecutionRejectionReason, PaymentEnvelope};
    let (inputs, outputs, repeated) = match workload {
        Workload::Payment { inputs, outputs } => (inputs, outputs, false),
        Workload::RepeatedCommitments => (2, 2, true),
        Workload::Conflicts | Workload::AnchorPruning => (1, 1, false),
        _ => return Err("not a payment workload".into()),
    };

    let fixture = PaymentFixture::new(inputs, outputs, repeated)?;
    let mut measurement = Measurement::default();
    let proof = prove_payment_body(
        &fixture.body,
        &fixture.anchor,
        &fixture.spends(),
        &fixture.outputs(),
        &mut measurement,
    )?;
    let a = MlDsa87SigningKey::generate()?;
    let b = MlDsa87SigningKey::generate()?;
    let c = MlDsa87SigningKey::generate()?;
    let mut policy = ExecutionPolicy::development()?;
    if workload == Workload::AnchorPruning {
        let mut bytes = encode_policy(&policy)?;
        bytes[136..144].copy_from_slice(&1_u64.to_le_bytes());
        policy = decode_policy(&bytes, DecodeLimits::reference())?;
    }

    let m = bootstrap(
        fixture.initial_leaves()?,
        inputs as u128 * 100,
        &[&a, &b, &c],
        &[0, 0, 0],
        &[0, 1, 2],
        policy,
    )?;
    let envelope = PaymentEnvelope::new(fixture.body.clone(), proof);
    let first = occurrence(envelope.clone().into(), 0, 11, 0);
    let units = match workload {
        Workload::Conflicts => vec![vec![first, occurrence(envelope.clone().into(), 1, 12, 0)]],
        Workload::AnchorPruning => {
            let mut units = vec![vec![first, occurrence(envelope.clone().into(), 0, 11, 1)]];
            for _ in 1..63 {
                units.push(vec![]);
            }

            units.push(vec![occurrence(envelope.into(), 1, 12, 0)]);
            units
        }
        _ => vec![vec![first]],
    };

    let public = run(m, units, measurement)?;
    let mut nullifiers = vec![];
    for checkpoint in &public.checkpoints {
        for output in checkpoint.accepted_outputs() {
            let OutputBody::Payment(body) = output.body() else {
                return Err("unexpected output family".into());
            };
            let owner = fixture.output_owner(output.output_index() as usize);
            let recovered = houseki_notes::recover_payment_output(
                body,
                output.output_index(),
                &owner.recipient,
                &owner.decryption,
                crate::payment_fixture::limits(),
                4096,
            )?;
            if recovered.commitment()? != output.output().commitment() {
                return Err("committed output recovery mismatch".into());
            }

            nullifiers.push(houseki_notes::derive_nullifier(
                &recovered,
                &owner.nullifier,
                &output.position(),
            )?);
        }
    }

    if repeated && (nullifiers.len() != 2 || nullifiers[0] == nullifiers[1]) {
        return Err("repeated commitments lost distinct note positions".into());
    }

    if workload == Workload::Conflicts {
        assert_eq!(
            public.checkpoints[0].receipts()[1].outcome(),
            ExecutionOutcome::Rejected(ExecutionRejectionReason::SpentNullifier)
        );
    }

    if workload == Workload::AnchorPruning {
        assert_eq!(public.checkpoints.len(), 65);
        assert_eq!(
            public.checkpoints.last().unwrap().receipts()[0].outcome(),
            ExecutionOutcome::Rejected(ExecutionRejectionReason::DisallowedAnchor)
        );
        assert_eq!(
            public.checkpoints.last().unwrap().state().anchors()[0]
                .sequence()
                .value(),
            2
        );
    }

    Ok(public)
}

/// Builds a real signed withdrawal and recovers only through its committed output context.
fn withdrawal_workload() -> Result<crate::PublicFixture, Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let context = ProofContext::new(fixture.body.context())?;
    let signature = fixture
        .authority
        .sign_reward_withdrawal(&fixture.body, context.body_limits())?;
    let mut measurement = crate::Measurement::default();
    let started = Instant::now();
    let proof = prove_reward_withdrawal(
        &ProofRuntime::new(),
        &fixture.body,
        &fixture.opening,
        &context,
        &CancellationToken::new(),
    )?;
    measurement.proving += started.elapsed();
    let b = houseki_crypto::MlDsa87SigningKey::generate()?;
    let c = houseki_crypto::MlDsa87SigningKey::generate()?;
    let m = crate::execution::bootstrap(
        vec![],
        0,
        &[&fixture.authority, &b, &c],
        &[100, 0, 0],
        &[0, 1, 2],
        ExecutionPolicy::development()?,
    )?;
    let occurrence = crate::execution::occurrence(
        RewardWithdrawalEnvelope::new(fixture.body.clone(), proof, signature).into(),
        1,
        12,
        0,
    );
    let public = crate::execution::run(m, vec![vec![occurrence]], measurement)?;
    for output in public.checkpoints[0].accepted_outputs() {
        let houseki_ledger::OutputBody::RewardWithdrawal(body) = output.body() else {
            return Err("unexpected payment output".into());
        };
        let recovered = houseki_notes::recover_withdrawal_output(
            body,
            &fixture.recipient,
            &fixture.decryption,
            4096,
        )?;
        assert_eq!(recovered.amount().atoms(), 3);
        assert_eq!(recovered.commitment()?, output.output().commitment());
    }

    assert_eq!(public.checkpoints[0].state().pool().atoms(), 3);
    Ok(public)
}
