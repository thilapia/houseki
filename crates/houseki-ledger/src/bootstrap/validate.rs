//! Independent expected-root validation before constructing any parent capability.

use crate::state::CommittedRecord;
use crate::{
    BootstrapCandidate, BootstrapError, BootstrapManifest, HeadRecord, ParentSnapshot,
    ReplayInputs, SnapshotRecord, StateCommitment, encode_snapshot,
};
use std::sync::Arc;

/// Bootstrap representation sealed after independent expected-state comparison.
pub struct ValidatedBootstrap {
    /// Actual reconstructed state and expected operational declarations.
    candidate: BootstrapCandidate,

    /// Complete public manifest retained for independent replay.
    manifest: Arc<BootstrapManifest>,
}

impl ValidatedBootstrap {
    /// Consumes the validated owner into its first immutable trusted snapshot.
    pub fn into_snapshot(self) -> ParentSnapshot {
        let candidate = self.candidate;
        let head = HeadRecord {
            sequence: candidate.sequence,
            artifact_id: candidate.parent_artifact_id,
            state_commitment: candidate.expected_state_commitment,
            source_cursor: candidate.source_cursor,
        };
        let record = Arc::new(CommittedRecord {
            state: candidate.state,
            head,
            artifact: None,
            receipts: vec![],
            effects: vec![],
            replay_inputs: ReplayInputs::Bootstrap(self.manifest),
        });
        ParentSnapshot {
            image: Arc::new(crate::store::StoreImage::bootstrap(record)),
        }
    }
}

/// Authenticates the actual rebuilt state against the independently expected fixture digest.
///
/// # Errors
///
/// Checks bounded manifest representation before cloning retained inputs, then rejects any
/// expected-state mismatch after exact canonical encoding and the registered reference hash.
pub fn validate_bootstrap(
    manifest: BootstrapManifest,
) -> Result<ValidatedBootstrap, BootstrapError> {
    manifest.check_bounds()?;
    let stream = crate::FixtureStreamId::from_bytes(houseki_crypto::ledger_fixture_order_stream(
        &crate::encode_fixture_stream(&crate::FixtureStreamRecord {
            network: manifest.network,
            starting_artifact_id: manifest.parent_artifact_id,
            unit_ids: manifest.fixture_unit_ids.clone(),
        })?,
    )?);
    match &manifest.source_cursor {
        crate::SourceCursor::Exhausted { stream_id }
            if *stream_id == stream && manifest.fixture_unit_ids.is_empty() => {}
        crate::SourceCursor::Unit {
            stream_id,
            ordinal,
            unit_id,
            offset,
        } if *stream_id == stream
            && *ordinal == 0
            && *offset == 0
            && manifest.fixture_unit_ids.first() == Some(unit_id) => {}
        _ => return Err(BootstrapError::SourceBinding),
    }
    let candidate = manifest.clone().candidate()?;
    let canonical = encode_snapshot(&SnapshotRecord::from_state(candidate.state())?)?;
    let actual = StateCommitment::from_bytes(houseki_crypto::ledger_reference_state(&canonical)?);
    if actual != candidate.expected_state_commitment {
        return Err(BootstrapError::StateCommitment);
    }
    Ok(ValidatedBootstrap {
        candidate,
        manifest: Arc::new(manifest),
    })
}

/// Trust sealing and committed-field binding tests.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::trusted_manifest;
    use crate::{SnapshotRecord, encode_snapshot};

    /// A correct reconstructed state remains untrusted until its independent digest matches.
    #[test]
    fn bootstrap_requires_expected_root() {
        let mut wrong = trusted_manifest();
        wrong.expected_state_commitment = crate::StateCommitment::from_bytes([9; 64]);
        assert!(matches!(
            validate_bootstrap(wrong),
            Err(crate::BootstrapError::StateCommitment)
        ));
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        assert_eq!(parent.state().pool().atoms(), 100);
        assert_eq!(parent.head().sequence().value(), 0);
        assert_eq!(parent.token().sequence().value(), 0);
        assert_eq!(
            encode_snapshot(&SnapshotRecord::from_state(parent.state()).unwrap()).unwrap(),
            include_bytes!("../../fixtures/reference-v1/bootstrap.bin")
        );
    }

    /// Complete-key sorting removes host insertion order from reference bytes.
    #[test]
    fn snapshot_sorting_is_canonical() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let mut record = SnapshotRecord::from_state(parent.state()).unwrap();
        record.spent = vec![
            houseki_types::Nullifier::from_bytes([2; 64]),
            houseki_types::Nullifier::from_bytes([1; 64]),
        ];
        let first = encode_snapshot(&record).unwrap();
        record.spent.reverse();
        assert_eq!(encode_snapshot(&record).unwrap(), first);
        record.spent.push(record.spent[0]);
        assert!(encode_snapshot(&record).is_err());
    }

    /// Each mutable or immutable logical field class contributes to its state commitment.
    #[test]
    fn state_commitment_binds_all_record_fields() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let record = SnapshotRecord::from_state(parent.state()).unwrap();
        let original =
            houseki_crypto::ledger_reference_state(&encode_snapshot(&record).unwrap()).unwrap();
        for change in 0..7 {
            let mut r = record.clone();
            match change {
                0 => {
                    r.accounts[0].1 = houseki_types::RewardAccount::new(
                        houseki_types::EncodedMlDsa87PublicKey::from_bytes([15; 2592]),
                        r.accounts[0].1.balance(),
                        r.accounts[0].1.next_nonce(),
                    )
                }
                1 => {
                    r.accounts[0].1 = houseki_types::RewardAccount::new(
                        r.accounts[0].1.withdrawal_authority().clone(),
                        houseki_types::Amount::from_atoms(1).unwrap(),
                        r.accounts[0].1.next_nonce(),
                    )
                }
                2 => {
                    r.accounts[0].1 = houseki_types::RewardAccount::new(
                        r.accounts[0].1.withdrawal_authority().clone(),
                        r.accounts[0].1.balance(),
                        houseki_types::WithdrawalNonce::new(1),
                    )
                }
                3 => r.policy.per_input_fee = houseki_types::Amount::from_atoms(0).unwrap(),
                4 => {
                    r.committee[0] = crate::CommitteeEntry::new(
                        r.committee[0].validator(),
                        2,
                        r.committee[0].reward_account(),
                        vec![6],
                    )
                }
                5 => {
                    r.committee[0] = crate::CommitteeEntry::new(
                        r.committee[0].validator(),
                        1,
                        r.committee[0].reward_account(),
                        vec![7],
                    )
                }
                _ => {
                    r.anchors[0] = crate::AnchorRecord::new(
                        houseki_types::CheckpointSequence::new(1),
                        r.anchors[0].anchor(),
                    )
                }
            }
            if change == 3 {
                r.policy.fee_schedule = houseki_types::FeeScheduleId::new(0xffff0002);
            }
            assert_ne!(
                houseki_crypto::ledger_reference_state(&encode_snapshot(&r).unwrap()).unwrap(),
                original
            );
        }
    }
}
