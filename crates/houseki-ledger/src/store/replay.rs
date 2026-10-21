//! Fresh public replay recomputes execution rather than applying reported archive effects.

use super::{ReferenceStore, ReplayArchive, ReplayError};
use crate::{AuthorizedUnit, BootstrapManifest, LedgerEngine, SourceCursor};
use houseki_proofs::ProofRuntime;

/// Rebuilds actual checkpoints with fresh complete-unit verification and exact public comparisons.
///
/// Archive effects and reported state remain comparison targets and are never applied as writes.
///
/// # Errors
///
/// Rejects independent bootstrap/source mismatch, missing complete unit payloads, cryptographic
/// failures or any difference in canonical outcomes, effects, state, leaves and continuation.
pub fn replay(
    manifest: BootstrapManifest,
    archive: &ReplayArchive,
    runtime: &ProofRuntime,
) -> Result<ReferenceStore, ReplayError> {
    let mut store = ReferenceStore::bootstrap(manifest)?;
    let initial = store.archive();
    if initial.network != archive.network
        || initial.starting_artifact != archive.starting_artifact
        || initial.starting_state != archive.starting_state
        || initial.stream_id != archive.stream_id
        || initial.unit_ids != archive.unit_ids
    {
        return Err(ReplayError::Mismatch(
            "independent bootstrap/source binding",
        ));
    }
    let verifier = if archive.expected.is_empty() {
        None
    } else {
        Some(crate::FixtureOrderVerifier::from_replay(
            &store.snapshot(),
            &archive.units,
        )?)
    };
    let mut authorized: Option<AuthorizedUnit> = None;
    let engine = LedgerEngine::new();
    for expected in &archive.expected {
        let parent = store.snapshot();
        let SourceCursor::Unit {
            ordinal, unit_id, ..
        } = parent.head().source_cursor()
        else {
            return Err(ReplayError::Mismatch(
                "unexpected checkpoint after source exhaustion",
            ));
        };
        if authorized.as_ref().map(|a| a.order_unit().unit_id()) != Some(*unit_id) {
            let index =
                usize::try_from(*ordinal).map_err(|_| ReplayError::Mismatch("source ordinal"))?;
            let raw = crate::RawOrderUnit::from_shared(std::sync::Arc::clone(
                archive
                    .units
                    .get(index)
                    .ok_or(ReplayError::Mismatch("missing complete unit"))?,
            ));
            let unit = verifier
                .as_ref()
                .expect("nonempty replay has a verified source")
                .verify_unit(raw)?;
            authorized = Some(engine.authorize_unit(&parent, unit, runtime)?);
        }
        let prepared =
            engine.prepare_next(&parent, authorized.as_ref().expect("unit authorized above"))?;
        if !expected.matches_record(&prepared.data.record)? {
            return Err(ReplayError::Mismatch("complete checkpoint records"));
        }
        store.commit(prepared)?;
    }
    if store.archive().to_bytes()? != archive.to_bytes()? {
        return Err(ReplayError::Mismatch(
            "complete canonical archive and authenticated anchor prerequisites",
        ));
    }
    Ok(store)
}

/// Actual cryptographic replay and partial-unit restart tests.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::{fixture_source_for, seed_fixture};
    use crate::{
        DecodeLimits, FixtureOrderVerifier, LedgerEngine, ReferenceStore, ReplayArchive,
        SnapshotRecord, StateCommitment, encode_snapshot,
    };
    use houseki_proofs::ProofRuntime;
    use houseki_types::Occurrence;

    /// A reduced count policy forces a two-envelope actual signed unit across two checkpoints.
    fn fixture() -> (
        crate::BootstrapManifest,
        ReferenceStore,
        crate::AuthorizedUnit,
    ) {
        let (mut m, original) = seed_fixture();
        m.policy.limits.batch_occurrences = 1;
        m.expected_state_commitment = StateCommitment::from_bytes(
            houseki_crypto::ledger_reference_state(
                &encode_snapshot(
                    &SnapshotRecord::from_state(m.clone().candidate().unwrap().state()).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let other = Occurrence::new(
            original.vertex_id(),
            original.vertex_author(),
            original.committee_context(),
            1,
            original.envelope().clone(),
        );
        let (parent, manifest, raw) = fixture_source_for(m, vec![vec![original, other]]);
        let crate::ReplayInputs::Bootstrap(m) = parent.replay_inputs() else {
            unreachable!()
        };
        let m = (**m).clone();
        let store = ReferenceStore::bootstrap(m.clone()).unwrap();
        let unit = FixtureOrderVerifier::new(manifest, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();
        let authorized = LedgerEngine::new()
            .authorize_unit(&parent, unit, &ProofRuntime::new())
            .unwrap();
        (m, store, authorized)
    }

    /// A fresh verifier reproduces every canonical public byte and excludes rejected outputs.
    #[test]
    fn replay_recomputes_instead_of_trusting_effects() {
        let (m, mut store, unit) = fixture();
        for _ in 0..2 {
            let candidate = LedgerEngine::new()
                .prepare_next(&store.snapshot(), &unit)
                .unwrap();
            store.commit(candidate).unwrap();
        }
        let bytes = store.archive().to_bytes().unwrap();
        let archive = ReplayArchive::from_bytes(&bytes, DecodeLimits::reference()).unwrap();
        let replayed = replay(m.clone(), &archive, &ProofRuntime::new()).unwrap();
        assert_eq!(replayed.archive().to_bytes().unwrap(), bytes);
        assert_eq!(replayed.snapshot().token(), store.snapshot().token());
        let mut bad = archive.clone();
        std::sync::Arc::make_mut(&mut bad.expected[0]).effects[0]
            .accepted
            .as_mut()
            .unwrap()
            .after_pool = houseki_types::Amount::from_atoms(9).unwrap();
        assert!(replay(m, &bad, &ProofRuntime::new()).is_err());
    }

    /// Full retained unit bytes are re-authorized after decoding a mid-unit archived prefix.
    #[test]
    fn resume_mid_unit_reauthorizes_complete_unit() {
        let (m, mut store, unit) = fixture();
        let first = LedgerEngine::new()
            .prepare_next(&store.snapshot(), &unit)
            .unwrap();
        store.commit(first).unwrap();
        let bytes = store.archive().to_bytes().unwrap();
        drop(unit);
        let archive = ReplayArchive::from_bytes(&bytes, DecodeLimits::reference()).unwrap();
        let mut restored = replay(m, &archive, &ProofRuntime::new()).unwrap();
        let raw = archive.verify_unit(&restored.snapshot(), 0).unwrap();
        let authorized = LedgerEngine::new()
            .authorize_unit(&restored.snapshot(), raw, &ProofRuntime::new())
            .unwrap();
        let next = LedgerEngine::new()
            .prepare_next(&restored.snapshot(), &authorized)
            .unwrap();
        assert_eq!(next.artifact().header().order.start_offset, 1);
        let result = restored.commit(next).unwrap().checkpoint();
        assert_eq!(result.accepted_outputs().count(), 0);
        assert_eq!(restored.snapshot().state().pool().atoms(), 3);
        assert_eq!(restored.snapshot().head().sequence().value(), 2);
    }

    /// Missing units, reordered checkpoints, tampered prerequisites and malformed outer lengths fail.
    #[test]
    fn replay_detects_missing_or_reordered_public_inputs() {
        let (m, mut store, unit) = fixture();
        for _ in 0..2 {
            let candidate = LedgerEngine::new()
                .prepare_next(&store.snapshot(), &unit)
                .unwrap();
            store.commit(candidate).unwrap();
        }
        let archive = store.archive();
        let mut missing = archive.clone();
        missing.units.clear();
        assert!(replay(m.clone(), &missing, &ProofRuntime::new()).is_err());
        let mut reordered = archive.clone();
        reordered.expected.reverse();
        assert!(replay(m.clone(), &reordered, &ProofRuntime::new()).is_err());
        let mut anchors = archive.clone();
        anchors.anchors[0] = crate::AnchorRecord::new(
            houseki_types::CheckpointSequence::new(99),
            anchors.anchors[0].anchor(),
        );
        assert!(replay(m, &anchors, &ProofRuntime::new()).is_err());
        let mut bytes = archive.to_bytes().unwrap();
        bytes.push(0);
        assert!(ReplayArchive::from_bytes(&bytes, DecodeLimits::reference()).is_err());
    }
}
