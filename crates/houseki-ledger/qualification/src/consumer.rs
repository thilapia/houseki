//! Fresh verifier-only replay over digest-bound public fixture files.

use crate::QualificationError;
use houseki_ledger::{
    BootstrapManifest, DecodeLimits, ExecutionArtifactId, FixtureStreamId, ReplayArchive,
    SnapshotRecord, SourceCursor, StateCommitment, decode_snapshot, replay,
};
use houseki_proofs::ProofRuntime;
use houseki_types::{
    CheckpointSequence, ExecutionOutcome, ExecutionProofStatus, FinalityStatus, NoteCommitment,
};
use sha3::{Digest, Sha3_512};
use std::{error::Error, fs, path::Path, time::Instant};

/// Verified native local replay observations without recipient recovery or consensus claims.
#[derive(Debug)]
pub struct VerificationSummary {
    /// Exact named public workload selected by the fixture producer.
    workload: String,

    /// Number of byte-identical reproduced checkpoints.
    checkpoints: usize,

    /// Identity and exact counts at every independently reproduced checkpoint.
    checkpoint_rows: Vec<crate::checkpoint_measurement::CheckpointMeasurement>,

    /// Accepted genuine occurrence results across the complete archive.
    accepted: usize,

    /// State-rejected genuine occurrence results across the complete archive.
    rejected: usize,

    /// Final reproduced position, without a global freshness assertion.
    sequence: u64,

    /// Complete serialized archive input bytes.
    archive_bytes: usize,

    /// Local fresh native replay duration.
    replay_ns: u128,

    /// Actual reference checkpoint consensus status.
    finality: FinalityStatus,

    /// Actual checkpoint execution-proof package status.
    execution_proof: ExecutionProofStatus,
}

impl VerificationSummary {
    /// Reports explicit fixture-local replay scope and distinct certification/recovery status.
    pub fn report(&self) -> String {
        let mut report = format!(
            "workload={}\nfixture_order=true\ncheckpoints={}\naccepted={}\nrejected={}\nsequence={}\narchive_bytes={}\nfresh_verifier_replay_ns={}\nconsensus_finality={:?}\nexecution_proof={:?}\nrecipient_recovery=not_established_by_replay\n",
            self.workload,
            self.checkpoints,
            self.accepted,
            self.rejected,
            self.sequence,
            self.archive_bytes,
            self.replay_ns,
            self.finality,
            self.execution_proof
        );
        report.push_str(&format!("checkpoint_rows={}\n", self.checkpoint_rows.len()));
        for checkpoint in &self.checkpoint_rows {
            report.push_str(&checkpoint.report());
        }
        report
    }
}

/// Verifies every pinned public file before decoding and freshly reproducing the complete archive.
pub fn verify(directory: &Path) -> Result<VerificationSummary, QualificationError> {
    verify_inner(directory).map_err(QualificationError::Native)
}

/// Reads one complete file with bounds checked both before and after its allocation.
fn read(directory: &Path, name: &str, maximum: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let path = directory.join(name);
    if fs::metadata(&path)?.len() as u128 > maximum as u128 {
        return Err("fixture file exceeds bound".into());
    }
    let bytes = fs::read(path)?;
    if bytes.len() > maximum {
        return Err("fixture file grew beyond bound".into());
    }
    Ok(bytes)
}

/// Decodes a complete public digest with exact width and no suffix bytes.
fn digest(bytes: &[u8]) -> Result<[u8; 64], Box<dyn Error>> {
    let text = std::str::from_utf8(bytes)?.trim();
    if text.len() != 128 || !text.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err("invalid public digest width".into());
    }
    let mut output = [0; 64];
    for (i, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)?;
    }
    Ok(output)
}

/// Loads independent trusted fixture declarations separately from reported replay state.
pub(crate) fn load(
    directory: &Path,
) -> Result<(String, BootstrapManifest, ReplayArchive), Box<dyn Error>> {
    let metadata = String::from_utf8(read(directory, "manifest.txt", 16384)?)?;
    if metadata.lines().next() != Some("houseki-ledger-public-fixture-v1")
        || !metadata.lines().any(|l| l == "fixture_order=true")
    {
        return Err("unsupported fixture manifest".into());
    }
    let workload = metadata
        .lines()
        .find_map(|l| l.strip_prefix("workload="))
        .ok_or("missing workload identity")?
        .to_owned();
    crate::Workload::parse(&workload).map_err(|e| Box::new(e) as Box<dyn Error>)?;
    let mut files = vec![];
    for (name, maximum) in [
        ("bootstrap-state.bin", 2_097_152),
        ("bootstrap-leaves.bin", 294_920),
        ("bootstrap-state.hex", 129),
        ("stream.hex", 129),
        ("archive.bin", 67_108_864),
    ] {
        let prefix = format!("{name}=");
        let mut matches = metadata
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix));
        let expected = digest(
            matches
                .next()
                .ok_or("missing pinned file digest")?
                .as_bytes(),
        )?;
        if matches.next().is_some() {
            return Err("duplicate pinned file digest".into());
        }
        let bytes = read(directory, name, maximum)?;
        if Sha3_512::digest(&bytes).as_slice() != expected {
            return Err("public fixture file digest mismatch".into());
        }
        files.push(bytes);
    }
    let record: SnapshotRecord = decode_snapshot(&files[0], DecodeLimits::reference())?;
    let archive = ReplayArchive::from_bytes(&files[4], DecodeLimits::reference())?;
    let state = StateCommitment::from_bytes(digest(&files[2])?);
    let stream = FixtureStreamId::from_bytes(digest(&files[3])?);
    let leafbytes = &files[1];
    if leafbytes.len() < 8 {
        return Err("truncated bootstrap leaves".into());
    }
    let count = usize::try_from(u64::from_le_bytes(leafbytes[..8].try_into()?))?;
    if count > 4096 || leafbytes.len() != 8 + count * 72 {
        return Err("invalid bootstrap leaf count".into());
    }
    let mut leaves = Vec::new();
    leaves.try_reserve_exact(count)?;
    for index in 0..count {
        let start = 8 + index * 72;
        if &leafbytes[start..start + 8] != 64_u64.to_le_bytes().as_slice() {
            return Err("invalid leaf record width".into());
        }
        leaves.push(NoteCommitment::from_bytes(
            leafbytes[start + 8..start + 72].try_into()?,
        ));
    }
    let ids = archive.unit_ids().to_vec();
    let cursor = if let Some(first) = ids.first() {
        SourceCursor::Unit {
            stream_id: stream,
            ordinal: 0,
            unit_id: *first,
            offset: 0,
        }
    } else {
        SourceCursor::Exhausted { stream_id: stream }
    };
    let manifest = BootstrapManifest {
        network: record.network,
        sequence: CheckpointSequence::new(0),
        parent_artifact_id: ExecutionArtifactId::from_bytes([0; 64]),
        expected_state_commitment: state,
        expected_note_anchor: record.note_anchor,
        source_cursor: cursor,
        fixture_unit_ids: ids,
        leaves,
        spent: record.spent,
        accounts: record.accounts,
        anchors: record.anchors,
        policy: record.policy,
        committee_context: record.committee_context,
        committee: record.committee,
        pool: record.pool,
        issued: record.issued,
    };
    Ok((workload, manifest, archive))
}

/// Runs public verification without enabling prover features or borrowing any wallet secret.
fn verify_inner(directory: &Path) -> Result<VerificationSummary, Box<dyn Error>> {
    let (workload, manifest, archive) = load(directory)?;
    let started = Instant::now();
    let store = replay(manifest, &archive, &ProofRuntime::new())?;
    let replay_ns = started.elapsed().as_nanos();
    let mut accepted = 0;
    let mut rejected = 0;
    let mut checkpoints = vec![];
    let parent = store.snapshot();
    // Native historical handles identify complete original-order results without semantic-ID collapse.
    let current = parent
        .artifact()
        .ok_or("qualification corpus has no executed checkpoint")?;
    let mut identity = current.identity();
    loop {
        let checkpoint = store
            .checkpoint(identity)
            .ok_or("missing reproduced historical checkpoint")?;
        for receipt in checkpoint.receipts() {
            match receipt.outcome() {
                ExecutionOutcome::Accepted => accepted += 1,
                ExecutionOutcome::Rejected(_) => rejected += 1,
            }
        }
        let previous = checkpoint.artifact().header().parent_artifact_id;
        checkpoints.push(checkpoint);
        if previous == ExecutionArtifactId::from_bytes([0; 64]) {
            break;
        }
        identity = previous;
    }
    checkpoints.reverse();
    crate::Workload::parse(&workload)?.validate_checkpoints(&checkpoints)?;
    let checkpoint = store
        .checkpoint(parent.head().artifact_id())
        .ok_or("missing final executed checkpoint")?;
    Ok(VerificationSummary {
        workload,
        checkpoints: archive.checkpoint_count(),
        checkpoint_rows: checkpoints
            .iter()
            .map(crate::checkpoint_measurement::CheckpointMeasurement::capture)
            .collect(),
        accepted,
        rejected,
        sequence: parent.head().sequence().value(),
        archive_bytes: archive.to_bytes()?.len(),
        replay_ns,
        finality: checkpoint.finality_status(),
        execution_proof: checkpoint.execution_proof_status(),
    })
}

/// Default-feature supervision tests require a deliberately generated complete public corpus.
#[cfg(test)]
mod verifier_consumer {
    use super::*;
    use crate::Workload;
    use houseki_ledger::{CommitResult, LedgerEngine, ReferenceStore};
    use std::path::PathBuf;

    /// Locates required generated inputs and fails explicitly when qualification was not prepared.
    fn corpus() -> PathBuf {
        PathBuf::from(std::env::var_os("HOUSEKI_LEDGER_PUBLIC_CORPUS").expect(
            "generate-all and set HOUSEKI_LEDGER_PUBLIC_CORPUS before verifier qualification tests",
        ))
    }

    /// Valid UTF-8 that is not hexadecimal returns an error without slicing code points.
    #[test]
    fn non_ascii_hexadecimal_metadata_returns_error() {
        let malformed = format!("0€{}", "0".repeat(124));
        assert_eq!(malformed.len(), 128);
        assert!(digest(malformed.as_bytes()).is_err());
    }

    /// Every documented workload is freshly checked in this separately built verifier-only graph.
    #[test]
    fn fresh_verifier_replays_every_public_workload() {
        for workload in Workload::all() {
            let summary = verify(&corpus().join(workload.name())).unwrap();
            assert!(summary.checkpoints > 0);
            assert_eq!(summary.finality, FinalityStatus::Unconfirmed);
            assert_eq!(summary.execution_proof, ExecutionProofStatus::Unverified);
        }
    }

    /// A consistently replayed rejection is insufficient to qualify an ordinary payment family.
    #[test]
    fn all_rejected_payment_cannot_qualify() {
        use houseki_ledger::{
            FixtureManifest, FixtureOrderVerifier, RawOrderUnit, encode_snapshot,
        };
        use houseki_types::{Amount, ExecutionRejectionReason};
        let source = corpus().join("1-1");
        let (_, mut manifest, archive) = load(&source).unwrap();
        manifest.pool = Amount::from_atoms(0).unwrap();
        manifest.issued = Amount::from_atoms(0).unwrap();
        let state = encode_snapshot(
            &SnapshotRecord::from_state(manifest.clone().candidate().unwrap().state()).unwrap(),
        )
        .unwrap();
        manifest.expected_state_commitment =
            StateCommitment::from_bytes(houseki_crypto::ledger_reference_state(&state).unwrap());
        let mut store = ReferenceStore::bootstrap(manifest.clone()).unwrap();
        let raw: Vec<_> = archive
            .source_units()
            .map(|bytes| RawOrderUnit::new(bytes.to_vec()))
            .collect();
        let verifier = FixtureOrderVerifier::new(
            FixtureManifest::new(manifest.network, manifest.parent_artifact_id, raw.clone()),
            &store.snapshot(),
        )
        .unwrap();
        let engine = LedgerEngine::new();
        let unit = engine
            .authorize_unit(
                &store.snapshot(),
                verifier.verify_unit(raw[0].clone()).unwrap(),
                &ProofRuntime::new(),
            )
            .unwrap();
        let prepared = engine.prepare_next(&store.snapshot(), &unit).unwrap();
        let checkpoint = store.commit(prepared).unwrap().checkpoint();
        assert_eq!(
            checkpoint.receipts()[0].outcome(),
            ExecutionOutcome::Rejected(ExecutionRejectionReason::StateBoundsExceeded)
        );
        let bytes = store.archive().to_bytes().unwrap();
        assert_eq!(
            replay(manifest.clone(), store.archive(), &ProofRuntime::new())
                .unwrap()
                .archive()
                .to_bytes()
                .unwrap(),
            bytes
        );
        let directory = std::env::temp_dir().join(format!(
            "houseki-ledger-all-rejected-{}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let mut metadata =
            "houseki-ledger-public-fixture-v1\nfixture_order=true\nworkload=1-1\n".to_owned();
        for (name, content) in [
            ("bootstrap-state.bin", state),
            (
                "bootstrap-leaves.bin",
                fs::read(source.join("bootstrap-leaves.bin")).unwrap(),
            ),
            (
                "bootstrap-state.hex",
                manifest
                    .expected_state_commitment
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    .into_bytes(),
            ),
            ("stream.hex", fs::read(source.join("stream.hex")).unwrap()),
            ("archive.bin", bytes),
        ] {
            let hash: String = Sha3_512::digest(&content)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            metadata.push_str(&format!("{name}={hash}\n"));
            fs::write(directory.join(name), content).unwrap();
        }
        fs::write(directory.join("manifest.txt"), metadata).unwrap();
        let result = verify(&directory);
        fs::remove_dir_all(&directory).unwrap();
        assert!(
            result.is_err(),
            "a rejected family must not qualify: {result:?}"
        );
    }

    /// Intact source bindings reject authorization-byte mutations before invented state receipts.
    #[test]
    fn public_mutations_fail_at_the_correct_boundary() {
        let (_, manifest, archive) = load(&corpus().join("withdrawal")).unwrap();
        let store = replay(manifest.clone(), &archive, &ProofRuntime::new()).unwrap();
        let bytes = archive.to_bytes().unwrap();
        let unit = houseki_ledger::decode_fixture_unit(
            archive.source_units().next().unwrap(),
            DecodeLimits::reference(),
        )
        .unwrap();
        let houseki_types::TransactionEnvelope::RewardWithdrawal(e) =
            unit.occurrences[0].envelope()
        else {
            unreachable!()
        };
        for sequence in [
            e.proof().as_bytes(),
            e.signature().as_bytes(),
            e.body().output().envelope().payload(),
        ] {
            let start = bytes
                .windows(sequence.len())
                .position(|w| w == sequence)
                .unwrap();
            for offset in [0, sequence.len() - 1] {
                let mut changed = bytes.clone();
                changed[start + offset] ^= 1;
                let decoded =
                    ReplayArchive::from_bytes(&changed, DecodeLimits::reference()).unwrap();
                assert!(matches!(
                    replay(manifest.clone(), &decoded, &ProofRuntime::new()),
                    Err(houseki_ledger::ReplayError::Order(_))
                ));
            }
        }
        let effects = houseki_ledger::encode_effects(store.snapshot().effects()).unwrap();
        let start = bytes
            .windows(effects.len())
            .position(|w| w == effects)
            .unwrap();
        let mut changed = bytes;
        let last = start + effects.len() - 16;
        changed[last] ^= 1;
        let changed = ReplayArchive::from_bytes(&changed, DecodeLimits::reference()).unwrap();
        assert!(matches!(
            replay(manifest, &changed, &ProofRuntime::new()),
            Err(houseki_ledger::ReplayError::Mismatch(_))
        ));
    }

    /// Exact historical retries preserve the newest complete head and the original output context.
    #[test]
    fn historical_retry_preserves_latest_head() {
        let (_, manifest, archive) = load(&corpus().join("value-loop")).unwrap();
        let mut store = ReferenceStore::bootstrap(manifest).unwrap();
        let engine = LedgerEngine::new();
        let runtime = ProofRuntime::new();
        let first = archive.verify_unit(&store.snapshot(), 0).unwrap();
        let first = engine
            .authorize_unit(&store.snapshot(), first, &runtime)
            .unwrap();
        let candidate = engine.prepare_next(&store.snapshot(), &first).unwrap();
        let retained = candidate.clone();
        let id = candidate.artifact().identity();
        store.commit(candidate).unwrap();
        let second = archive.verify_unit(&store.snapshot(), 1).unwrap();
        let second = engine
            .authorize_unit(&store.snapshot(), second, &runtime)
            .unwrap();
        let candidate = engine.prepare_next(&store.snapshot(), &second).unwrap();
        store.commit(candidate).unwrap();
        let token = store.snapshot().token();
        assert!(matches!(
            store.commit(retained).unwrap(),
            CommitResult::AlreadyCommitted(_)
        ));
        assert_eq!(store.snapshot().token(), token);
        assert_eq!(store.checkpoint(id).unwrap().accepted_outputs().count(), 3);
        assert_eq!(store.snapshot().state().pool().atoms(), 97);
    }

    /// Two independent public stores publish identical original-order prefixes and recovery views.
    #[test]
    fn independent_stores_publish_identical_prefixes() {
        let (_, manifest, archive) = load(&corpus().join("value-loop")).unwrap();
        let mut a = ReferenceStore::bootstrap(manifest.clone()).unwrap();
        let mut b = ReferenceStore::bootstrap(manifest).unwrap();
        let engine = LedgerEngine::new();
        for ordinal in 0..archive.source_unit_count() as u64 {
            let ua = engine
                .authorize_unit(
                    &a.snapshot(),
                    archive.verify_unit(&a.snapshot(), ordinal).unwrap(),
                    &ProofRuntime::new(),
                )
                .unwrap();
            let ub = engine
                .authorize_unit(
                    &b.snapshot(),
                    archive.verify_unit(&b.snapshot(), ordinal).unwrap(),
                    &ProofRuntime::new(),
                )
                .unwrap();
            let pa = engine.prepare_next(&a.snapshot(), &ua).unwrap();
            let pb = engine.prepare_next(&b.snapshot(), &ub).unwrap();
            assert_eq!(
                pa.artifact().canonical_header().unwrap(),
                pb.artifact().canonical_header().unwrap()
            );
            let ca = a.commit(pa).unwrap().checkpoint();
            let cb = b.commit(pb).unwrap().checkpoint();
            assert_eq!(ca.effects(), cb.effects());
            assert_eq!(ca.receipts(), cb.receipts());
            assert_eq!(
                ca.accepted_outputs()
                    .map(|o| (
                        o.origin(),
                        o.output_index(),
                        o.position(),
                        o.output().clone()
                    ))
                    .collect::<Vec<_>>(),
                cb.accepted_outputs()
                    .map(|o| (
                        o.origin(),
                        o.output_index(),
                        o.position(),
                        o.output().clone()
                    ))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                a.archive().to_bytes().unwrap(),
                b.archive().to_bytes().unwrap()
            );
        }
    }
}
