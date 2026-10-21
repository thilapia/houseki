//! Representation validation before independent bootstrap commitment authentication.

mod candidate;
mod committee;
mod error;
mod validate;

pub use candidate::BootstrapCandidate;
pub use committee::CommitteeEntry;
pub use error::BootstrapError;
pub use validate::{ValidatedBootstrap, validate_bootstrap};

use crate::{AnchorRecord, ExecutionPolicy, LogicalState, SourceCursor};
use houseki_crypto::MlDsa87VerificationKey;
use houseki_state::NoteTree;
use houseki_types::{
    Amount, CheckpointSequence, CommitteeContext, NetworkId, NoteCommitment, NoteTreeAnchor,
    Nullifier, RewardAccount, RewardAccountId,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Complete public bootstrap declarations supplied under local fixture trust.
///
/// Candidate validation checks representation and accounting before a later independent
/// commitment comparison establishes a trusted parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapManifest {
    /// Network for note trees and registered authority derivation.
    pub network: NetworkId,

    /// Declared parent checkpoint sequence.
    pub sequence: CheckpointSequence,

    /// Complete declared parent artifact identity.
    pub parent_artifact_id: crate::ExecutionArtifactId,

    /// Independently expected state digest checked in the artifact stage.
    pub expected_state_commitment: crate::StateCommitment,

    /// Expected actual note network, root and count.
    pub expected_note_anchor: NoteTreeAnchor,

    /// Declared continuation whose source binding is checked by the order adapter.
    pub source_cursor: SourceCursor,

    /// Complete finite source identity list bound by the independently expected fixture stream.
    pub fixture_unit_ids: Vec<crate::FixtureUnitId>,

    /// Actual ordered initial leaves, including repeated commitments.
    pub leaves: Vec<NoteCommitment>,

    /// Initial spent markers, required to be empty for generated fixtures.
    pub spent: Vec<Nullifier>,

    /// Declared registrations retained as a list so duplicate keys remain observable.
    pub accounts: Vec<(RewardAccountId, RewardAccount)>,

    /// Complete retained anchor history in checkpoint order.
    pub anchors: Vec<AnchorRecord>,

    /// Fixed execution policy for the generated ledger.
    pub policy: ExecutionPolicy,

    /// Fixed epoch and declared committee identity.
    pub committee_context: CommitteeContext,

    /// Declared validator registrations and fee mappings.
    pub committee: Vec<CommitteeEntry>,

    /// Declared shielded allocation under explicit fixture trust.
    pub pool: Amount,

    /// Fixed bounded supply conserved across every transition.
    pub issued: Amount,
}

impl BootstrapManifest {
    /// Checks policy and every manifest collection before retained input cloning.
    pub(crate) fn check_bounds(&self) -> Result<(), BootstrapError> {
        self.policy.validate()?;
        if self.fixture_unit_ids.len() as u128 > u128::from(self.policy.limits().fixture_units()) {
            return Err(BootstrapError::Capacity);
        }
        let limits = self.policy.limits();
        if self.leaves.len() as u128 > u128::from(limits.note_leaves())
            || self.spent.len() as u128 > u128::from(limits.spent_markers())
            || self.accounts.len() as u128 > u128::from(limits.accounts())
            || self.committee.len() as u128 > u128::from(limits.validators())
            || self.anchors.len() as u128 > u128::from(limits.anchor_retention())
            || self.committee.iter().any(|e| {
                e.key_descriptor().len() as u128 > u128::from(limits.key_descriptor_bytes())
            })
        {
            return Err(BootstrapError::Capacity);
        }
        Ok(())
    }

    /// Reconstructs and validates a bounded candidate without authenticating its state digest.
    ///
    /// # Errors
    ///
    /// Checks policy, list capacities and initial spent state before duplicate registrations,
    /// account derivation, committee mappings, conservation and exact tree/history metadata.
    pub fn candidate(self) -> Result<BootstrapCandidate, BootstrapError> {
        self.check_bounds()?;
        let limits = self.policy.limits();
        if !self.spent.is_empty() {
            return Err(BootstrapError::InitialSpent);
        }
        let mut accounts = HashMap::new();
        accounts
            .try_reserve(self.accounts.len())
            .map_err(|_| BootstrapError::Allocation)?;
        for (id, account) in self.accounts {
            if accounts.contains_key(id.as_bytes()) {
                return Err(BootstrapError::DuplicateAccount);
            }
            if MlDsa87VerificationKey::from_encoded(account.withdrawal_authority())
                .reward_account_id(self.network)?
                != id
            {
                return Err(BootstrapError::AccountIdentity);
            }
            accounts.insert(id.into_bytes(), account);
        }
        let mut committee = HashMap::new();
        committee
            .try_reserve(self.committee.len())
            .map_err(|_| BootstrapError::Allocation)?;
        let mut weight = 0_u128;
        for entry in self.committee {
            if committee.contains_key(entry.validator().as_bytes()) {
                return Err(BootstrapError::DuplicateValidator);
            }
            if entry.weight() == 0 {
                return Err(BootstrapError::CommitteeWeight);
            }
            weight = weight
                .checked_add(entry.weight())
                .ok_or(BootstrapError::CommitteeWeight)?;
            if !accounts.contains_key(entry.reward_account().as_bytes()) {
                return Err(BootstrapError::UnknownBeneficiary);
            }
            committee.insert(entry.validator().into_bytes(), entry);
        }
        if weight == 0 {
            return Err(BootstrapError::CommitteeWeight);
        }
        let sum = accounts
            .values()
            .try_fold(self.pool.atoms(), |sum, a| {
                sum.checked_add(a.balance().atoms())
            })
            .ok_or(BootstrapError::Conservation)?;
        if sum != self.issued.atoms() || sum > Amount::MAX_ATOMS {
            return Err(BootstrapError::Conservation);
        }
        let mut tree = NoteTree::new(self.network)?;
        // Every retained descriptor must match the actual tree prefix for its count.
        let check_prefix = |actual: NoteTreeAnchor| {
            if self.anchors.iter().any(|record| {
                record.anchor().count() == actual.count() && record.anchor() != actual
            }) {
                Err(BootstrapError::History)
            } else {
                Ok(())
            }
        };
        check_prefix(tree.anchor())?;
        for &leaf in &self.leaves {
            tree.append(leaf)?;
            check_prefix(tree.anchor())?;
        }
        if tree.anchor() != self.expected_note_anchor {
            return Err(BootstrapError::NoteAnchor);
        }
        let expected_history = self
            .sequence
            .value()
            .saturating_add(1)
            .min(limits.anchor_retention());
        if self.anchors.len() as u128 != u128::from(expected_history) {
            return Err(BootstrapError::History);
        }
        let start = self.sequence.value() - (expected_history - 1);
        let mut previous_count = 0;
        for (i, record) in self.anchors.iter().enumerate() {
            let anchor = record.anchor();
            if record.sequence().value() != start + i as u64
                || anchor.network_id() != self.network
                || anchor.count().value() > self.leaves.len() as u128
                || anchor.count().value() < previous_count
            {
                return Err(BootstrapError::History);
            }
            for prior in &self.anchors[..i] {
                if prior.anchor().root() == anchor.root() && prior.anchor() != anchor {
                    return Err(BootstrapError::History);
                }
            }
            previous_count = anchor.count().value();
        }
        if self.anchors.last().map(AnchorRecord::anchor) != Some(tree.anchor()) {
            return Err(BootstrapError::History);
        }
        Ok(BootstrapCandidate {
            state: LogicalState {
                network: self.network,
                tree,
                leaves: self.leaves,
                spent: HashMap::new(),
                accounts,
                anchors: self.anchors,
                policy: Arc::new(self.policy),
                committee_context: self.committee_context,
                committee: Arc::new(committee),
                pool: self.pool,
                issued: self.issued,
            },
            sequence: self.sequence,
            parent_artifact_id: self.parent_artifact_id,
            expected_state_commitment: self.expected_state_commitment,
            source_cursor: self.source_cursor,
        })
    }
}

/// Bootstrap validation tests use deliberately malformed public candidates.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use crate::test_support::manifest;
    use crate::{AnchorRecord, BootstrapError, CommitteeEntry};
    use houseki_types::{
        Amount, CheckpointSequence, NetworkId, NoteCount, NoteTreeAnchor, Nullifier, RewardAccount,
        RewardAccountId,
    };

    /// Detects duplicate keys before replacement and checks complete authority derivation.
    #[test]
    fn candidate_rejects_duplicate_keys_and_bad_accounts() {
        let mut m = manifest();
        m.accounts.push(m.accounts[0].clone());
        assert!(matches!(
            m.candidate(),
            Err(BootstrapError::DuplicateAccount)
        ));
        let mut m = manifest();
        m.committee.push(m.committee[0].clone());
        assert!(matches!(
            m.candidate(),
            Err(BootstrapError::DuplicateValidator)
        ));
        let mut m = manifest();
        m.accounts[0].0 = RewardAccountId::from_bytes([0; 64]);
        assert!(matches!(
            m.candidate(),
            Err(BootstrapError::AccountIdentity)
        ));
        let mut m = manifest();
        m.network = NetworkId::from_bytes([8; 64]);
        assert!(m.candidate().is_err());
        let mut m = manifest();
        let entry = &m.committee[0];
        m.committee[0] = CommitteeEntry::new(
            entry.validator(),
            1,
            RewardAccountId::from_bytes([0; 64]),
            vec![],
        );
        assert!(matches!(
            m.candidate(),
            Err(BootstrapError::UnknownBeneficiary)
        ));
    }

    /// Checks aggregate conservation, global supply and every manifest list bound.
    #[test]
    fn candidate_checks_supply_and_capacities() {
        let mut m = manifest();
        m.pool = Amount::from_atoms(99).unwrap();
        assert!(matches!(m.candidate(), Err(BootstrapError::Conservation)));
        let mut m = manifest();
        m.pool = Amount::from_atoms(Amount::MAX_ATOMS).unwrap();
        let (_, account) = &m.accounts[0];
        m.accounts[0].1 = RewardAccount::new(
            account.withdrawal_authority().clone(),
            Amount::from_atoms(1).unwrap(),
            account.next_nonce(),
        );
        m.issued = m.pool;
        assert!(matches!(m.candidate(), Err(BootstrapError::Conservation)));
        for (which, count) in [(0, 4097), (1, 65), (2, 4097), (3, 65)] {
            let mut m = manifest();
            match which {
                0 => m.leaves = vec![m.leaves[0]; count],
                1 => m.accounts = vec![m.accounts[0].clone(); count],
                2 => m.spent = vec![Nullifier::from_bytes([1; 64]); count],
                _ => m.committee = vec![m.committee[0].clone(); count],
            }
            assert!(matches!(m.candidate(), Err(BootstrapError::Capacity)));
        }
        let mut m = manifest();
        m.spent.push(Nullifier::from_bytes([1; 64]));
        assert!(matches!(m.candidate(), Err(BootstrapError::InitialSpent)));
        for (weight, descriptor) in [(0, 0), (1, 16385)] {
            let mut m = manifest();
            let entry = &m.committee[0];
            m.committee[0] = CommitteeEntry::new(
                entry.validator(),
                weight,
                entry.reward_account(),
                vec![0; descriptor],
            );
            assert!(m.candidate().is_err());
        }
        let mut m = manifest();
        let entry = &m.committee[0];
        m.committee = vec![
            CommitteeEntry::new(entry.validator(), u128::MAX, entry.reward_account(), vec![]),
            CommitteeEntry::new(
                houseki_types::ValidatorId::from_bytes([10; 64]),
                1,
                entry.reward_account(),
                vec![],
            ),
        ];
        assert!(matches!(
            m.candidate(),
            Err(BootstrapError::CommitteeWeight)
        ));
        assert!(Amount::from_le_bytes([255; 16]).is_err());
        manifest()
            .candidate()
            .unwrap()
            .state()
            .validate_conservation()
            .unwrap();
    }

    /// Checks retained roots against the actual prefix at each recorded count.
    #[test]
    fn history_roots_match_actual_leaf_prefixes() {
        let mut m = manifest();
        m.sequence = CheckpointSequence::new(1);
        m.anchors[0] = AnchorRecord::new(
            CheckpointSequence::new(0),
            NoteTreeAnchor::new(
                m.network,
                NoteCount::new(0).unwrap(),
                houseki_types::NoteRoot::from_bytes([99; 64]),
            ),
        );
        m.anchors
            .push(AnchorRecord::new(m.sequence, m.expected_note_anchor));
        assert!(matches!(m.candidate(), Err(BootstrapError::History)));
    }

    /// Preserves repeated roots while rejecting inconsistent descriptors and missing history.
    #[test]
    fn candidate_checks_anchor_history() {
        let mut m = manifest();
        m.sequence = CheckpointSequence::new(1);
        m.anchors
            .push(AnchorRecord::new(m.sequence, m.expected_note_anchor));
        assert!(m.candidate().is_ok());
        let mut m = manifest();
        m.anchors.clear();
        assert!(matches!(m.candidate(), Err(BootstrapError::History)));
        let mut m = manifest();
        m.sequence = CheckpointSequence::new(1);
        let conflicting = NoteTreeAnchor::new(
            m.network,
            NoteCount::new(0).unwrap(),
            m.expected_note_anchor.root(),
        );
        m.anchors.push(AnchorRecord::new(m.sequence, conflicting));
        assert!(m.candidate().is_err());
        let mut m = manifest();
        m.expected_note_anchor = NoteTreeAnchor::new(
            m.network,
            NoteCount::new(0).unwrap(),
            m.expected_note_anchor.root(),
        );
        assert!(matches!(m.candidate(), Err(BootstrapError::NoteAnchor)));
    }
}
