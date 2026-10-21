//! Public API only source construction and synchronous native qualification execution.

use crate::{Measurement, PublicFixture};
use houseki_crypto::MlDsa87SigningKey;
use houseki_ledger::{
    AnchorRecord, BootstrapManifest, CommitteeEntry, ExecutionArtifactId, ExecutionPolicy,
    FixtureManifest, FixtureOrderVerifier, FixtureStreamId, FixtureStreamRecord, FixtureUnitId,
    FixtureUnitRecord, LedgerEngine, RawOrderUnit, ReferenceStore, SnapshotRecord, SourceCursor,
    StateCommitment, encode_fixture_stream, encode_fixture_unit, encode_occurrences,
    encode_snapshot, replay,
};
use houseki_proofs::{ProofContext, ProofRuntime};
use houseki_state::NoteTree;
use houseki_types::{
    Amount, CheckpointSequence, CommitteeContext, CommitteeId, Epoch, NetworkId, NoteCommitment,
    Occurrence, RewardAccount, TransactionEnvelope, ValidatorId, VertexId, WithdrawalNonce,
};
use std::{error::Error, path::PathBuf, time::Instant};

/// Constructs actual public state from original commitments and registered authority
/// owners.
pub(crate) fn bootstrap(
    leaves: Vec<NoteCommitment>,
    pool: u128,
    keys: &[&MlDsa87SigningKey],
    balances: &[u128],
    mapping: &[usize],
    policy: ExecutionPolicy,
) -> Result<BootstrapManifest, Box<dyn Error>> {
    let network = NetworkId::from_bytes([7; 64]);
    let mut tree = NoteTree::new(network)?;
    for &leaf in &leaves {
        tree.append(leaf)?;
    }

    let accounts: Vec<_> = keys
        .iter()
        .zip(balances)
        .map(|(key, balance)| {
            Ok((
                key.verification_key().reward_account_id(network)?,
                RewardAccount::new(
                    key.verification_key().to_encoded(),
                    Amount::from_atoms(*balance)?,
                    WithdrawalNonce::new(0),
                ),
            ))
        })
        .collect::<Result<_, Box<dyn Error>>>()?;

    let committee = mapping
        .iter()
        .enumerate()
        .map(|(author, account)| {
            CommitteeEntry::new(
                ValidatorId::from_bytes([5 + author as u8; 64]),
                1,
                accounts[*account].0,
                vec![6],
            )
        })
        .collect();

    let issued = balances
        .iter()
        .try_fold(pool, |sum, b| sum.checked_add(*b))
        .ok_or("fixture issued amount overflow")?;
    Ok(BootstrapManifest {
        network,
        sequence: CheckpointSequence::new(0),
        parent_artifact_id: ExecutionArtifactId::from_bytes([0; 64]),
        expected_state_commitment: StateCommitment::from_bytes([0; 64]),
        expected_note_anchor: tree.anchor(),
        source_cursor: SourceCursor::Exhausted {
            stream_id: FixtureStreamId::from_bytes([0; 64]),
        },
        fixture_unit_ids: vec![],
        leaves,
        spent: vec![],
        accounts,
        anchors: vec![AnchorRecord::new(CheckpointSequence::new(0), tree.anchor())],
        policy,
        committee_context: CommitteeContext::new(Epoch::new(0), CommitteeId::from_bytes([3; 64])),
        committee,
        pool: Amount::from_atoms(pool)?,
        issued: Amount::from_atoms(issued)?,
    })
}

/// Binds all complete ordered units before constructing the independently expected stream.
fn source(
    mut m: BootstrapManifest,
    units: Vec<Vec<Occurrence>>,
) -> Result<(BootstrapManifest, FixtureManifest, Vec<RawOrderUnit>), Box<dyn Error>> {
    let mut previous = FixtureUnitId::from_bytes([0; 64]);
    let mut raw = vec![];
    let mut ids = vec![];
    for (ordinal, occurrences) in units.into_iter().enumerate() {
        let bytes = encode_fixture_unit(&FixtureUnitRecord {
            ordinal: ordinal as u64,
            previous_unit_id: previous,
            occurrences,
        })?;
        previous = FixtureUnitId::from_bytes(houseki_crypto::ledger_fixture_order_unit(&bytes)?);
        ids.push(previous);
        raw.push(RawOrderUnit::new(bytes));
    }

    let stream = FixtureStreamId::from_bytes(houseki_crypto::ledger_fixture_order_stream(
        &encode_fixture_stream(&FixtureStreamRecord {
            network: m.network,
            starting_artifact_id: m.parent_artifact_id,
            unit_ids: ids.clone(),
        })?,
    )?);
    m.fixture_unit_ids = ids;
    m.source_cursor = if let Some(first) = m.fixture_unit_ids.first() {
        SourceCursor::Unit {
            stream_id: stream,
            ordinal: 0,
            unit_id: *first,
            offset: 0,
        }
    } else {
        SourceCursor::Exhausted { stream_id: stream }
    };
    m.expected_state_commitment =
        StateCommitment::from_bytes(houseki_crypto::ledger_reference_state(&encode_snapshot(
            &SnapshotRecord::from_state(m.clone().candidate()?.state())?,
        )?)?);
    let manifest = FixtureManifest::new(m.network, m.parent_artifact_id, raw.clone());
    Ok((m, manifest, raw))
}

/// Executes complete units, measures distinct phases and independently replays every public
/// record.
pub(crate) fn run(
    manifest: BootstrapManifest,
    units: Vec<Vec<Occurrence>>,
    mut measurement: Measurement,
) -> Result<PublicFixture, Box<dyn Error>> {
    for unit in &units {
        measurement.component_bytes += encode_occurrences(unit)?.len() as u64;
        for occurrence in unit {
            match occurrence.envelope() {
                TransactionEnvelope::Payment(e) => {
                    measurement.proof_bytes += e.proof().byte_len() as u64;
                    measurement.body_bytes += e
                        .body()
                        .to_bytes(ProofContext::new(e.body().context())?.body_limits())?
                        .len() as u64;
                }
                TransactionEnvelope::RewardWithdrawal(e) => {
                    measurement.proof_bytes += e.proof().byte_len() as u64;
                    measurement.body_bytes += e
                        .body()
                        .to_bytes(ProofContext::new(e.body().context())?.body_limits())?
                        .len() as u64;
                }
            }
        }
    }

    let (manifest, fixture, raw) = source(manifest, units)?;
    let mut store = ReferenceStore::bootstrap(manifest.clone())?;
    let started = Instant::now();
    let verifier = FixtureOrderVerifier::new(fixture, &store.snapshot())?;
    measurement.order += started.elapsed();
    let engine = LedgerEngine::new();
    let runtime = ProofRuntime::new();
    let mut checkpoints = vec![];
    for raw in raw {
        let started = Instant::now();
        let unit = verifier.verify_unit(raw)?;
        measurement.order += started.elapsed();
        let identity = unit.unit_id();
        let started = Instant::now();
        let authorized = engine.authorize_unit(&store.snapshot(), unit, &runtime)?;
        measurement.authorization += started.elapsed();
        while matches!(
            store.snapshot().head().source_cursor(),
            SourceCursor::Unit { unit_id, .. } if *unit_id == identity
        ) {
            let prepared = engine.prepare_next(&store.snapshot(), &authorized)?;
            measurement.preparation(prepared.metrics());
            let started = Instant::now();
            let checkpoint = store.commit(prepared)?.checkpoint();
            measurement.publication += started.elapsed();
            measurement.checkpoint(&checkpoint)?;
            checkpoints.push(checkpoint);
        }
    }

    let archive = store.archive().clone();
    let started = Instant::now();
    let reproduced = replay(manifest.clone(), &archive, &ProofRuntime::new())?;
    measurement.replay += started.elapsed();
    if reproduced.archive().to_bytes()? != archive.to_bytes()? {
        return Err("native replay bytes differ".into());
    }

    measurement.archive(&archive)?;
    Ok(PublicFixture {
        directory: PathBuf::new(),
        manifest,
        archive,
        checkpoints,
        measurement,
    })
}

/// Creates one genuine occurrence with explicit author and complete vertex payload slot.
pub(crate) fn occurrence(
    envelope: TransactionEnvelope,
    author: usize,
    vertex: u8,
    index: u64,
) -> Occurrence {
    Occurrence::new(
        VertexId::from_bytes([vertex; 64]),
        ValidatorId::from_bytes([5 + author as u8; 64]),
        CommitteeContext::new(Epoch::new(0), CommitteeId::from_bytes([3; 64])),
        index,
        envelope,
    )
}
