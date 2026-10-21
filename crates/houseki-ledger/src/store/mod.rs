//! Atomic in-memory reference publication, historical queries and independent public replay.

mod archive;
mod error;
mod expected;
mod image;
mod native;
mod output;
mod projection;
mod result;

pub use archive::ReplayArchive;
pub use error::{CommitError, ReplayError};
pub(crate) use expected::ExpectedCheckpoint;
pub(crate) use image::StoreImage;
pub(crate) use native::NativeCheckpoint;
pub use output::{AcceptedOutput, OutputBody};
pub use result::{CommitResult, CommittedCheckpoint};

#[cfg(all(test, feature = "experimental-profiles"))]
use crate::test_support::failure::{FailurePoint, hit};
use crate::{
    BootstrapError, BootstrapManifest, ExecutionArtifactId, ParentSnapshot, PreparedCheckpoint,
    SnapshotRecord, encode_snapshot, validate_bootstrap,
};
use houseki_types::{Receipt, VertexId};
use std::sync::Arc;

/// One writer publishing complete immutable in-memory fixture execution images.
pub struct ReferenceStore {
    /// The sole publication owner swapped only after every fallible update succeeds.
    image: Arc<StoreImage>,
}

impl ReferenceStore {
    /// Validates independent bootstrap/state/source bindings before constructing the initial store.
    pub fn bootstrap(manifest: BootstrapManifest) -> Result<Self, BootstrapError> {
        let snapshot = validate_bootstrap(manifest)?.into_snapshot();
        Ok(Self {
            image: snapshot.image,
        })
    }

    /// Returns one complete consistent state/head/archive image retained independently by readers.
    pub fn snapshot(&self) -> ParentSnapshot {
        ParentSnapshot {
            image: Arc::clone(&self.image),
        }
    }

    /// Borrows the complete public replay archive for this exact current image.
    pub fn archive(&self) -> &ReplayArchive {
        &self.image.history
    }

    /// Publishes a complete candidate or returns its exact retained historical success.
    ///
    /// # Errors
    ///
    /// Checks canonical historical retry contents before parent conflicts, then constructs all
    /// archive/index/return owners before the only publication swap.
    pub fn commit(&mut self, prepared: PreparedCheckpoint) -> Result<CommitResult, CommitError> {
        let identity = prepared.artifact().identity();
        if let Some((index, entry)) = self
            .image
            .history
            .native
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.record.head.artifact_id() == identity)
        {
            if !self
                .image
                .history
                .expected
                .get(index)
                .ok_or(CommitError::Integrity)?
                .matches_record(&entry.record)?
            {
                return Err(CommitError::Integrity);
            }
            if entry.parent != *prepared.expected_parent()
                || !same_record(&entry.record, &prepared.data.record)?
            {
                return Err(CommitError::Integrity);
            }
            return Ok(CommitResult::AlreadyCommitted(CommittedCheckpoint {
                image: Arc::clone(&self.image),
                record: Arc::clone(&entry.record),
            }));
        }
        if self.snapshot().token() != *prepared.expected_parent() {
            return Err(CommitError::ParentChanged);
        }
        let history = self.image.history.appended(&prepared)?;
        #[cfg(all(test, feature = "experimental-profiles"))]
        if hit(FailurePoint::ArchiveReserve) {
            return Err(CommitError::Allocation);
        }
        let image = Arc::new(StoreImage {
            current: Arc::clone(&prepared.data.record),
            history,
        });
        let result = CommitResult::Published(CommittedCheckpoint {
            image: Arc::clone(&image),
            record: Arc::clone(&prepared.data.record),
        });
        #[cfg(all(test, feature = "experimental-profiles"))]
        if hit(FailurePoint::Publish) {
            return Err(CommitError::Allocation);
        }
        self.image = image;
        Ok(result)
    }

    /// Returns an actual retained historical checkpoint without implying global freshness.
    pub fn checkpoint(&self, identity: ExecutionArtifactId) -> Option<CommittedCheckpoint> {
        self.image
            .history
            .native
            .iter()
            .find(|entry| entry.record.head.artifact_id() == identity)
            .map(|entry| CommittedCheckpoint {
                image: Arc::clone(&self.image),
                record: Arc::clone(&entry.record),
            })
    }

    /// Resolves one occurrence outcome by exact artifact, vertex and payload position.
    pub fn receipt(
        &self,
        artifact: ExecutionArtifactId,
        vertex: VertexId,
        index: u64,
    ) -> Option<Receipt> {
        self.checkpoint(artifact)?
            .receipts()
            .iter()
            .find(|r| r.vertex_id() == vertex && r.transaction_index() == index)
            .copied()
    }
}

/// Compares complete retained canonical contents instead of trusting digest equality alone.
fn same_record(
    a: &crate::state::CommittedRecord,
    b: &crate::state::CommittedRecord,
) -> Result<bool, CommitError> {
    Ok(a.head == b.head
        && a.artifact == b.artifact
        && a.receipts == b.receipts
        && a.effects == b.effects
        && a.replay_inputs == b.replay_inputs
        && a.state.leaves() == b.state.leaves()
        && encode_snapshot(&SnapshotRecord::from_state(&a.state)?)?
            == encode_snapshot(&SnapshotRecord::from_state(&b.state)?)?)
}

/// Complete publication and retained-candidate retry tests.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::eligibility::authorize_for_test;
    use crate::test_support::{execution::payment, fixture_source_for, trusted_manifest};
    use crate::{FixtureOrderVerifier, LedgerEngine, validate_bootstrap};
    use houseki_types::ValidatorId;

    /// Creates one complete bounded source with enough occurrences to exercise historical retries.
    fn fixture() -> (ReferenceStore, crate::AuthorizedUnit) {
        let m = trusted_manifest();
        let base = validate_bootstrap(m.clone()).unwrap().into_snapshot();
        let occurrences = (0..65)
            .map(|i| payment(base.state(), i, 10, ValidatorId::from_bytes([5; 64])))
            .collect();
        let (parent, manifest, raw) = fixture_source_for(m, vec![occurrences]);
        let crate::ReplayInputs::Bootstrap(m) = parent.replay_inputs() else {
            unreachable!()
        };
        let store = ReferenceStore::bootstrap((**m).clone()).unwrap();
        let unit = FixtureOrderVerifier::new(manifest, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();
        let authorized = authorize_for_test(&parent, unit).unwrap();
        (store, authorized)
    }

    /// Old readers retain all old state/history while publication exposes one complete new image.
    #[test]
    fn publication_is_one_complete_image() {
        let (mut store, unit) = fixture();
        let old = store.snapshot();
        let candidate = LedgerEngine::new().prepare_next(&old, &unit).unwrap();
        let identity = candidate.artifact().identity();
        let result = store.commit(candidate).unwrap();
        assert!(matches!(result, CommitResult::Published(_)));
        assert_eq!(old.head().sequence().value(), 0);
        assert!(old.receipts().is_empty());
        assert_eq!(store.snapshot().head().sequence().value(), 1);
        assert_eq!(store.snapshot().receipts().len(), 64);
        assert_eq!(
            store.checkpoint(identity).unwrap().artifact().identity(),
            identity
        );
    }

    /// Every actual prepublication failure preserves state, head, cursor and replay archive together.
    #[test]
    fn prepublication_failure_preserves_every_component() {
        use crate::test_support::failure::{FailurePoint, inject};
        let (mut store, unit) = fixture();
        let old = store.archive().to_bytes().unwrap();
        let token = store.snapshot().token();
        let candidate = LedgerEngine::new()
            .prepare_next(&store.snapshot(), &unit)
            .unwrap();
        for point in [FailurePoint::ArchiveReserve, FailurePoint::Publish] {
            let _injection = inject(point);
            assert!(store.commit(candidate.clone()).is_err());
            assert_eq!(store.snapshot().token(), token);
            assert_eq!(store.archive().to_bytes().unwrap(), old);
        }
    }

    /// An exact retained candidate returns original recorded success even after a newer checkpoint.
    #[test]
    fn historical_retry_survives_later_head() {
        let (mut store, unit) = fixture();
        let candidate = LedgerEngine::new()
            .prepare_next(&store.snapshot(), &unit)
            .unwrap();
        let retained = candidate.clone();
        let id = candidate.artifact().identity();
        store.commit(candidate).unwrap();
        let next = LedgerEngine::new()
            .prepare_next(&store.snapshot(), &unit)
            .unwrap();
        store.commit(next).unwrap();
        let head = store.snapshot().token();
        assert!(matches!(
            store.commit(retained).unwrap(),
            CommitResult::AlreadyCommitted(_)
        ));
        assert_eq!(store.snapshot().token(), head);
        assert_eq!(store.checkpoint(id).unwrap().accepted_outputs().count(), 2);
        assert_eq!(store.snapshot().state().pool().atoms(), 96);
    }

    /// Context-preserving output views include every accepted append exactly once and exclude rejections.
    #[test]
    fn accepted_output_view_is_complete_and_context_preserving() {
        let (mut store, unit) = fixture();
        let candidate = LedgerEngine::new()
            .prepare_next(&store.snapshot(), &unit)
            .unwrap();
        let id = candidate.artifact().identity();
        store.commit(candidate).unwrap();
        let checkpoint = store.checkpoint(id).unwrap();
        let outputs: Vec<_> = checkpoint.accepted_outputs().collect();
        assert_eq!(outputs.len(), 2);
        assert_eq!(
            (outputs[0].position().value(), outputs[1].position().value()),
            (1, 2)
        );
        assert_eq!(
            outputs[0].output().commitment(),
            outputs[1].output().commitment()
        );
        assert_eq!(outputs[0].occurrence_index(), 0);
        assert_eq!(outputs[1].output_index(), 1);
        assert!(matches!(outputs[0].body(), OutputBody::Payment(_)));
    }
    /// A different private test candidate for a consumed parent is a conflict, never idempotent success.
    #[test]
    fn different_candidate_for_consumed_parent_fails() {
        let (mut store, unit) = fixture();
        let original = LedgerEngine::new()
            .prepare_next(&store.snapshot(), &unit)
            .unwrap();
        let mut different = LedgerEngine::new()
            .prepare_next(&store.snapshot(), &unit)
            .unwrap();
        let data = std::sync::Arc::get_mut(&mut different.data).unwrap();
        let record = std::sync::Arc::get_mut(&mut data.record).unwrap();
        let artifact = record.artifact.as_mut().unwrap();
        artifact.header.post_state = crate::StateCommitment::from_bytes([99; 64]);
        artifact.identity = crate::ExecutionArtifactId::from_bytes(
            houseki_crypto::ledger_execution_artifact(&artifact.canonical_header().unwrap())
                .unwrap(),
        );
        record.head.artifact_id = artifact.identity;
        store.commit(original).unwrap();
        assert!(matches!(
            store.commit(different),
            Err(CommitError::ParentChanged)
        ));
    }

    /// Historical retry refuses corrupt retained comparison records rather than trusting one digest.
    #[test]
    fn corrupted_history_cannot_return_retry_success() {
        let (mut store, unit) = fixture();
        let candidate = LedgerEngine::new()
            .prepare_next(&store.snapshot(), &unit)
            .unwrap();
        let retained = candidate.clone();
        store.commit(candidate).unwrap();
        let image = std::sync::Arc::get_mut(&mut store.image).unwrap();
        std::sync::Arc::make_mut(&mut image.history.expected[0]).cursor =
            crate::SourceCursor::Exhausted {
                stream_id: crate::FixtureStreamId::from_bytes([99; 64]),
            };
        assert!(matches!(
            store.commit(retained),
            Err(CommitError::Integrity)
        ));
    }
}
