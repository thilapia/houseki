//! Complete disposable checkpoint preparation without publication.

mod data;
mod error;
mod measurement;
mod prepared;

pub use error::PreparationError;
pub use measurement::PreparationMetrics;
pub use prepared::PreparedCheckpoint;

#[cfg(all(test, feature = "experimental-profiles"))]
use crate::test_support::failure::{FailurePoint, hit};
use crate::{
    AnchorRecord, AuthorizedUnit, EffectRecord, ExecutionArtifact, ExecutionArtifactId,
    ExecutionPolicyId, HeadRecord, LedgerEngine, LogicalState, ParentSnapshot, ReplayInputs,
    SnapshotRecord, StateCommitment, WorkingState, encode_artifact_header, encode_effects,
    encode_occurrences, encode_policy, encode_receipts, encode_snapshot,
};
use crate::{
    execution::{self, Decision},
    order::next_range,
    state::CommittedRecord,
};
use houseki_types::{ExecutionOutcome, NoteOutput, Occurrence, Receipt, TransactionEnvelope};
use std::{sync::Arc, time::Instant};

impl LedgerEngine {
    /// Prepares one greedily derived range against an independent disposable working state.
    ///
    /// Every outcome, effect, commitment and replay prerequisite is complete before return.
    ///
    /// # Errors
    ///
    /// Reports parent/dependency/source inconsistency before state work and aborts the entire
    /// candidate on every local reconstruction, application, allocation or commitment failure.
    pub fn prepare_next(
        &self,
        parent: &ParentSnapshot,
        unit: &AuthorizedUnit,
    ) -> Result<PreparedCheckpoint, PreparationError> {
        let total_started = Instant::now();
        parent.state().validate_conservation()?;
        let parent_bytes = encode_snapshot(&SnapshotRecord::from_state(parent.state())?)?;
        if StateCommitment::from_bytes(houseki_crypto::ledger_reference_state(&parent_bytes)?)
            != parent.head().state_commitment()
            || parent.state().anchors().last().map(|a| a.sequence())
                != Some(parent.head().sequence())
        {
            return Err(PreparationError::Integrity);
        }
        unit.require_compatible(parent)?;
        let rules = crate::CheckpointRules::derive(parent.state(), parent.head().sequence())?;
        let range = next_range(
            parent.head().source_cursor(),
            unit.order_unit(),
            rules.policy(),
        )?;
        let reconstruction_started = Instant::now();
        let mut working = WorkingState::reconstruct(parent.state())?;
        let reconstruction = reconstruction_started.elapsed();
        let execution_started = Instant::now();
        #[cfg(all(test, feature = "experimental-profiles"))]
        if hit(FailurePoint::Reconstruct) {
            return Err(PreparationError::Allocation);
        }
        let mut receipts = Vec::new();
        let mut effects = Vec::new();
        receipts
            .try_reserve_exact(range.host.len())
            .map_err(|_| PreparationError::Allocation)?;
        effects
            .try_reserve_exact(range.host.len())
            .map_err(|_| PreparationError::Allocation)?;
        for index in range.host.clone() {
            let occurrence = unit.occurrence(index).ok_or(PreparationError::Integrity)?;
            let (outcome, effect) = match execution::evaluate(&rules, &working, &occurrence)? {
                Decision::Accept(delta) => (ExecutionOutcome::Accepted, working.apply(delta)?),
                Decision::Reject(reason) => (
                    ExecutionOutcome::Rejected(reason),
                    EffectRecord {
                        vertex_id: occurrence.occurrence().vertex_id(),
                        transaction_index: occurrence.occurrence().transaction_index(),
                        accepted: None,
                    },
                ),
            };
            receipts.push(Receipt::new(
                occurrence.occurrence().vertex_id(),
                occurrence.occurrence().transaction_index(),
                outcome,
            ));
            effects.push(effect);
        }
        working
            .state
            .anchors
            .try_reserve(1)
            .map_err(|_| PreparationError::Allocation)?;
        working.state.anchors.push(AnchorRecord::new(
            rules.sequence(),
            working.state.note_anchor(),
        ));
        let retention = usize::try_from(rules.policy().limits().anchor_retention())
            .map_err(|_| PreparationError::Integrity)?;
        if working.state.anchors.len() > retention {
            let remove = working.state.anchors.len() - retention;
            working.state.anchors.drain(..remove);
        }
        #[cfg(all(test, feature = "experimental-profiles"))]
        if hit(FailurePoint::AnchorPrune) {
            return Err(PreparationError::Allocation);
        }
        working.validate_conservation()?;
        let occurrences = &unit.order_unit().occurrences()[range.host.clone()];
        validate_alignment(
            parent.state(),
            working.state(),
            occurrences,
            &receipts,
            &effects,
        )?;
        let execution = execution_started.elapsed();
        let commitments_started = Instant::now();
        let post_state = StateCommitment::from_bytes(houseki_crypto::ledger_reference_state(
            &encode_snapshot(&SnapshotRecord::from_state(working.state())?)?,
        )?);
        boundary("state")?;
        let occurrences_root =
            houseki_crypto::ledger_ordered_occurrences(&encode_occurrences(occurrences)?)?;
        boundary("occurrences")?;
        let receipts_root = houseki_crypto::ledger_receipts(&encode_receipts(&receipts)?)?;
        boundary("receipts")?;
        let effects_root = houseki_crypto::ledger_public_effects(&encode_effects(&effects)?)?;
        boundary("effects")?;
        let system_events_root = houseki_crypto::ledger_system_events(&0_u64.to_le_bytes())?;
        boundary("events")?;
        let policy_id = ExecutionPolicyId::from_bytes(houseki_crypto::ledger_execution_policy(
            &encode_policy(rules.policy())?,
        )?);
        boundary("policy")?;
        let header = crate::ArtifactHeader {
            schema: 1,
            policy_id,
            network: working.state.network(),
            sequence: rules.sequence(),
            committee_context: working.state.committee_context(),
            parent_artifact_id: parent.head().artifact_id(),
            pre_state: parent.head().state_commitment(),
            post_state,
            order: range.binding,
            occurrences_root,
            occurrence_count: occurrences.len() as u64,
            receipts_root,
            effects_root,
            system_events_root,
        };
        let identity = ExecutionArtifactId::from_bytes(houseki_crypto::ledger_execution_artifact(
            &encode_artifact_header(&header)?,
        )?);
        boundary("artifact")?;
        let commitments = commitments_started.elapsed();
        let artifact = ExecutionArtifact {
            header,
            identity,
            occurrences: unit.order_unit().occurrences_owner(),
            range: range.host,
            receipts: receipts.clone(),
            effects: effects.clone(),
        };
        let trusted_anchors: Vec<_> = unit.trusted_anchors().collect();
        let replay_inputs = ReplayInputs::Execution {
            source_unit: unit.order_unit().canonical_owner(),
            unit_ids: Arc::from(parent.source_unit_ids()),
            trusted_anchors: trusted_anchors.into(),
        };
        let head = HeadRecord {
            sequence: rules.sequence(),
            artifact_id: identity,
            state_commitment: post_state,
            source_cursor: range.next_cursor,
        };
        let record = CommittedRecord {
            state: working.state,
            head,
            artifact: Some(artifact),
            receipts,
            effects,
            replay_inputs,
        };
        #[cfg(all(test, feature = "experimental-profiles"))]
        if hit(FailurePoint::Seal) {
            return Err(PreparationError::Allocation);
        }
        let metrics = PreparationMetrics {
            reconstruction,
            execution,
            commitments,
            total: total_started.elapsed(),
        };
        Ok(PreparedCheckpoint::seal(parent.token(), record, metrics))
    }
}

/// Verifies complete receipt/effect/output alignment before any candidate can be sealed.
fn validate_alignment(
    before: &LogicalState,
    after: &LogicalState,
    occurrences: &[Occurrence],
    receipts: &[Receipt],
    effects: &[EffectRecord],
) -> Result<(), PreparationError> {
    if occurrences.len() != receipts.len() || occurrences.len() != effects.len() {
        return Err(PreparationError::Integrity);
    }
    let mut next = before.note_anchor().count().value();
    let mut pool = before.pool();
    for ((occurrence, receipt), effect) in occurrences.iter().zip(receipts).zip(effects) {
        if receipt.vertex_id() != occurrence.vertex_id()
            || receipt.transaction_index() != occurrence.transaction_index()
            || effect.vertex_id != occurrence.vertex_id()
            || effect.transaction_index != occurrence.transaction_index()
        {
            return Err(PreparationError::Integrity);
        }
        match (receipt.outcome(), &effect.accepted) {
            (ExecutionOutcome::Rejected(_), None) => {}
            (ExecutionOutcome::Accepted, Some(accepted)) => {
                let outputs: &[NoteOutput] = match occurrence.envelope() {
                    TransactionEnvelope::Payment(e) => {
                        if accepted.nullifiers != e.body().inputs().nullifiers() {
                            return Err(PreparationError::Integrity);
                        }
                        e.body().outputs().outputs()
                    }
                    TransactionEnvelope::RewardWithdrawal(e) => {
                        if !accepted.nullifiers.is_empty() {
                            return Err(PreparationError::Integrity);
                        }
                        std::slice::from_ref(e.body().output())
                    }
                };
                if outputs.len() != accepted.appends.len() || accepted.before_pool != pool {
                    return Err(PreparationError::Integrity);
                }
                for (output, append) in outputs.iter().zip(&accepted.appends) {
                    if u128::from(append.position.value()) != next
                        || append.commitment != output.commitment()
                    {
                        return Err(PreparationError::Integrity);
                    }
                    let position =
                        usize::try_from(next).map_err(|_| PreparationError::Integrity)?;
                    if after.leaves().get(position) != Some(&append.commitment) {
                        return Err(PreparationError::Integrity);
                    }
                    next = next.checked_add(1).ok_or(PreparationError::Integrity)?;
                }
                pool = accepted.after_pool;
            }
            _ => return Err(PreparationError::Integrity),
        }
    }
    if next != after.note_anchor().count().value() || pool != after.pool() {
        return Err(PreparationError::Integrity);
    }
    Ok(())
}

/// Injects a local commitment failure only in private tests at an actual completed boundary.
fn boundary(_kind: &'static str) -> Result<(), PreparationError> {
    #[cfg(all(test, feature = "experimental-profiles"))]
    if hit(FailurePoint::Commitment(_kind)) {
        return Err(PreparationError::Allocation);
    }
    Ok(())
}

/// Prepared candidate and deterministic abort tests.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use crate::eligibility::authorize_for_test;
    use crate::test_support::{execution::payment, fixture_source_for, trusted_manifest};
    use crate::{
        FixtureOrderVerifier, LedgerEngine, SnapshotRecord, encode_snapshot, validate_bootstrap,
    };
    use houseki_types::ValidatorId;

    /// Produces an owned synthetic unit for state mechanics without weakening production checks.
    fn fixture(count: usize) -> (crate::ParentSnapshot, crate::AuthorizedUnit) {
        let m = trusted_manifest();
        let base = validate_bootstrap(m.clone()).unwrap().into_snapshot();
        let occurrences = (0..count)
            .map(|i| payment(base.state(), i as u64, 10, ValidatorId::from_bytes([5; 64])))
            .collect();
        let (parent, manifest, raw) = fixture_source_for(m, vec![occurrences]);
        let unit = FixtureOrderVerifier::new(manifest, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();
        let authorized = authorize_for_test(&parent, unit).unwrap();
        (parent, authorized)
    }

    /// Every origin receives exactly one aligned receipt/effect while only accepted outputs append.
    #[test]
    fn prepare_matches_order_and_seals_all_records() {
        let (parent, unit) = fixture(3);
        let before = encode_snapshot(&SnapshotRecord::from_state(parent.state()).unwrap()).unwrap();
        let token = parent.token();
        let prepared = LedgerEngine::new().prepare_next(&parent, &unit).unwrap();
        assert_eq!(prepared.receipts().len(), 3);
        assert_eq!(prepared.effects().len(), 3);
        assert_eq!(prepared.artifact().header().sequence.value(), 1);
        assert_eq!(prepared.post_state().pool().atoms(), 96);
        assert_eq!(prepared.post_state().leaves().len(), 3);
        assert!(prepared.effects()[0].accepted.is_some());
        assert!(prepared.effects()[1].accepted.is_none());
        assert_eq!(parent.token(), token);
        assert_eq!(
            encode_snapshot(&SnapshotRecord::from_state(parent.state()).unwrap()).unwrap(),
            before
        );
        assert_eq!(
            prepared.effects()[0]
                .accepted
                .as_ref()
                .unwrap()
                .appends
                .iter()
                .map(|a| a.position.value())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    /// Empty protocol units still bind context and advance exactly once.
    #[test]
    fn empty_unit_produces_one_bound_artifact() {
        let (parent, unit) = fixture(0);
        let prepared = LedgerEngine::new().prepare_next(&parent, &unit).unwrap();
        assert!(prepared.receipts().is_empty());
        assert_eq!(prepared.post_state().anchors().len(), 2);
        assert!(matches!(
            prepared.next_cursor(),
            crate::SourceCursor::Exhausted { .. }
        ));
    }

    /// Retained candidate clones share identical canonical summaries and expected parent identity.
    #[test]
    fn cloned_candidate_is_identical() {
        let (parent, unit) = fixture(1);
        let prepared = LedgerEngine::new().prepare_next(&parent, &unit).unwrap();
        let clone = prepared.clone();
        assert_eq!(
            prepared.artifact().canonical_header().unwrap(),
            clone.artifact().canonical_header().unwrap()
        );
        assert_eq!(prepared.expected_parent(), clone.expected_parent());
        assert_eq!(prepared.effects(), clone.effects());
    }

    /// Each actual preparation boundary aborts without changing any committed parent component.
    #[test]
    fn every_preparation_failpoint_preserves_parent() {
        use crate::test_support::failure::{FailurePoint as F, inject};
        let (parent, unit) = fixture(2);
        let token = parent.token();
        let state = encode_snapshot(&SnapshotRecord::from_state(parent.state()).unwrap()).unwrap();
        for point in [
            F::Reconstruct,
            F::NullifierInsert(0),
            F::NullifierInsert(1),
            F::NoteAppend(0),
            F::NoteAppend(1),
            F::AccountReplace(0),
            F::PoolReplace,
            F::AnchorPrune,
            F::Commitment("state"),
            F::Commitment("occurrences"),
            F::Commitment("receipts"),
            F::Commitment("effects"),
            F::Commitment("events"),
            F::Commitment("policy"),
            F::Commitment("artifact"),
            F::Seal,
        ] {
            let _injection = inject(point);
            assert!(
                LedgerEngine::new().prepare_next(&parent, &unit).is_err(),
                "{point:?}"
            );
            assert_eq!(parent.token(), token);
            assert_eq!(
                encode_snapshot(&SnapshotRecord::from_state(parent.state()).unwrap()).unwrap(),
                state
            );
            assert!(parent.receipts().is_empty());
        }
    }
    /// A newly recorded root becomes eligible only under the following checkpoint's fixed view.
    #[test]
    fn same_checkpoint_new_anchor_is_ineligible() {
        let (parent, unit) = fixture(1);
        let prepared = LedgerEngine::new().prepare_next(&parent, &unit).unwrap();
        let before =
            crate::CheckpointRules::derive(parent.state(), parent.head().sequence()).unwrap();
        assert!(!before.allows_anchor(prepared.post_state().note_anchor()));
        let next = crate::CheckpointRules::derive(
            prepared.post_state(),
            houseki_types::CheckpointSequence::new(1),
        )
        .unwrap();
        assert!(next.allows_anchor(prepared.post_state().note_anchor()));
    }

    /// Incomplete, duplicated or mismatched output/effect joins cannot seal a checkpoint.
    #[test]
    fn accepted_appends_match_exact_body_outputs() {
        let (parent, unit) = fixture(1);
        let prepared = LedgerEngine::new().prepare_next(&parent, &unit).unwrap();
        let original = prepared.effects().to_vec();
        for change in 0..3 {
            let mut effects = original.clone();
            let accepted = effects[0].accepted.as_mut().unwrap();
            match change {
                0 => {
                    accepted.appends.pop();
                }
                1 => accepted.appends[1].position = accepted.appends[0].position,
                _ => {
                    accepted.appends[0].commitment =
                        houseki_types::NoteCommitment::from_bytes([99; 64])
                }
            };
            assert!(
                super::validate_alignment(
                    parent.state(),
                    prepared.post_state(),
                    prepared.artifact().occurrences(),
                    prepared.receipts(),
                    &effects
                )
                .is_err()
            );
        }
    }

    /// Independent native executors produce complete identical summaries through each unit slice.
    #[test]
    fn independent_executors_construct_the_same_checkpoint() {
        let (mut a, unit_a) = fixture(65);
        let (mut b, unit_b) = fixture(65);
        for _ in 0..2 {
            let left = LedgerEngine::new().prepare_next(&a, &unit_a).unwrap();
            let right = LedgerEngine::new().prepare_next(&b, &unit_b).unwrap();
            assert_eq!(
                left.artifact().canonical_header().unwrap(),
                right.artifact().canonical_header().unwrap()
            );
            assert_eq!(left.receipts(), right.receipts());
            assert_eq!(left.effects(), right.effects());
            assert_eq!(
                left.next_cursor().to_bytes(),
                right.next_cursor().to_bytes()
            );
            assert_eq!(
                encode_snapshot(&SnapshotRecord::from_state(left.post_state()).unwrap()).unwrap(),
                encode_snapshot(&SnapshotRecord::from_state(right.post_state()).unwrap()).unwrap()
            );
            a = crate::ParentSnapshot {
                image: std::sync::Arc::new(crate::store::StoreImage {
                    current: std::sync::Arc::clone(&left.data.record),
                    history: a.image.history.clone(),
                }),
            };
            b = crate::ParentSnapshot {
                image: std::sync::Arc::new(crate::store::StoreImage {
                    current: std::sync::Arc::clone(&right.data.record),
                    history: b.image.history.clone(),
                }),
            };
        }
        assert!(matches!(
            a.head().source_cursor(),
            crate::SourceCursor::Exhausted { .. }
        ));
        assert!(LedgerEngine::new().prepare_next(&a, &unit_a).is_err());
    }

    /// An invalid late proof in a byte-sliced complete unit prevents the first candidate.
    #[test]
    fn invalid_last_proof_cannot_prepare_first_slice() {
        use crate::test_support::seed_fixture;
        use houseki_types::{
            EncodedTransactionProof, Occurrence, RewardWithdrawalEnvelope, TransactionEnvelope,
        };
        let (m, original) = seed_fixture();
        let mut occurrences = vec![];
        for index in 0..10 {
            let envelope = if index == 9 {
                let TransactionEnvelope::RewardWithdrawal(e) = original.envelope() else {
                    unreachable!()
                };
                let mut proof = e.proof().as_bytes().to_vec();
                proof[0] ^= 1;
                RewardWithdrawalEnvelope::new(
                    e.body().clone(),
                    EncodedTransactionProof::new(proof, 2097152).unwrap(),
                    e.signature().clone(),
                )
                .into()
            } else {
                original.envelope().clone()
            };
            occurrences.push(Occurrence::new(
                original.vertex_id(),
                original.vertex_author(),
                original.committee_context(),
                index,
                envelope,
            ));
        }
        let (parent, manifest, raw) = fixture_source_for(m, vec![occurrences]);
        let unit = FixtureOrderVerifier::new(manifest, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();
        assert!(
            LedgerEngine::new()
                .authorize_unit(&parent, unit, &houseki_proofs::ProofRuntime::new())
                .is_err()
        );
        assert_eq!(parent.head().sequence().value(), 0);
        assert!(parent.receipts().is_empty());
    }
}
