//! Immutable recognition dependencies distinct from checkpoint activation.

use super::anchor::resolve_anchor;
use crate::{
    CommitteeEntry, ParentSnapshot, UnitPreparationError, VerifiedOrderUnit, encode_policy,
};
use houseki_crypto::MlDsa87VerificationKey;
use houseki_proofs::ProofContext;
use houseki_types::{
    CommitteeContext, EncodedMlDsa87PublicKey, NetworkId, NoteTreeAnchor, RewardAccountId,
    RewardWithdrawalBody, TransactionContext, TransactionEnvelope, TransactionKind,
};

/// Exact private recognition implementation revision.
const VERIFIER_REGISTRY_REVISION: u32 = 1;

/// Structural immutable compatibility across independently executed slices.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Compatibility {
    /// Local registry interpretation revision.
    registry_revision: u32,

    /// Account and anchor interpretation network.
    network: NetworkId,

    /// Exact complete canonical policy bytes.
    policy: Vec<u8>,

    /// Sorted complete source identities and immutable public authorities.
    authorities: Vec<(RewardAccountId, EncodedMlDsa87PublicKey)>,

    /// Fixed epoch and committee identity.
    committee_context: CommitteeContext,

    /// Complete sorted immutable validator registrations.
    committee: Vec<CommitteeEntry>,
}

impl Compatibility {
    /// Captures immutable interpretation while excluding balances, nonces, spent and history.
    pub(super) fn capture(parent: &ParentSnapshot) -> Result<Self, UnitPreparationError> {
        let mut authorities = Vec::new();
        authorities
            .try_reserve_exact(parent.state().accounts.len())
            .map_err(|_| UnitPreparationError::Allocation)?;
        authorities.extend(parent.state().accounts().map(|(id, a)| {
            (
                RewardAccountId::from_bytes(*id),
                a.withdrawal_authority().clone(),
            )
        }));
        authorities.sort_unstable_by_key(|a| a.0.into_bytes());
        let mut committee = Vec::new();
        committee
            .try_reserve_exact(parent.state().committee.len())
            .map_err(|_| UnitPreparationError::Allocation)?;
        committee.extend(parent.state().committee().cloned());
        committee.sort_unstable_by_key(|c| c.validator().into_bytes());
        Ok(Self {
            registry_revision: VERIFIER_REGISTRY_REVISION,
            network: parent.state().network(),
            policy: encode_policy(parent.state().policy())?,
            authorities,
            committee_context: parent.state().committee_context(),
            committee,
        })
    }
}

/// Exact contexts and authenticated descriptors frozen before cryptographic calls.
#[derive(Debug)]
pub(super) struct UnitDependencies {
    /// Expected contexts aligned with canonical occurrence order.
    pub(super) contexts: Vec<ProofContext>,

    /// Trusted payment anchors aligned with all occurrence positions.
    pub(super) anchors: Vec<Option<NoteTreeAnchor>>,

    /// Complete immutable interpretation under which the unit was checked.
    pub(super) compatibility: Compatibility,
}

/// Recognizes the exact body claim before checking its independently selected family.
pub(super) fn recognize(
    kind: TransactionKind,
    context: TransactionContext,
) -> Result<ProofContext, UnitPreparationError> {
    let recognized = ProofContext::new(context)?;
    let required = match kind {
        TransactionKind::Payment => 0xffff0008,
        TransactionKind::RewardWithdrawal => 0xffff0007,
    };
    if context.proof_profile_id().value() != required {
        return Err(UnitPreparationError::Relation);
    }
    Ok(recognized)
}

/// Checks closed registration and network-bound authority without consulting balance or nonce.
pub(super) fn require_authority(
    parent: &ParentSnapshot,
    body: &RewardWithdrawalBody,
) -> Result<(), UnitPreparationError> {
    let account = parent
        .state()
        .account(body.reward_account_id())
        .ok_or(UnitPreparationError::UnknownAccount)?;
    if account.withdrawal_authority() != body.withdrawal_public_key()
        || body.context().network_id() != parent.state().network()
        || MlDsa87VerificationKey::from_encoded(account.withdrawal_authority())
            .reward_account_id(body.context().network_id())?
            != body.reward_account_id()
    {
        return Err(UnitPreparationError::Authority);
    }
    Ok(())
}

/// Resolves immutable expected inputs without applying any evolving state acceptance rule.
pub(super) fn resolve_dependencies(
    parent: &ParentSnapshot,
    unit: &VerifiedOrderUnit,
) -> Result<UnitDependencies, UnitPreparationError> {
    let ordinal = usize::try_from(unit.ordinal()).map_err(|_| UnitPreparationError::InputBound)?;
    if unit.stream_id() != parent.head().source_cursor().stream_id()
        || parent.source_unit_ids().get(ordinal) != Some(&unit.unit_id())
    {
        return Err(UnitPreparationError::InputBound);
    }
    let mut contexts = Vec::new();
    let mut anchors = Vec::new();
    contexts
        .try_reserve_exact(unit.occurrences().len())
        .map_err(|_| UnitPreparationError::Allocation)?;
    anchors
        .try_reserve_exact(unit.occurrences().len())
        .map_err(|_| UnitPreparationError::Allocation)?;
    for occurrence in unit.occurrences() {
        if occurrence.committee_context() != parent.state().committee_context()
            || parent
                .state()
                .beneficiary(occurrence.vertex_author())
                .is_none()
        {
            return Err(UnitPreparationError::InputBound);
        }
        match occurrence.envelope() {
            TransactionEnvelope::Payment(e) => {
                let body = e.body();
                let context = recognize(TransactionKind::Payment, body.context())?;
                if body.encoded_len(context.body_limits())? as u128
                    > u128::from(parent.state().policy().limits().body_bytes())
                    || e.proof().byte_len() as u128
                        > u128::from(parent.state().policy().limits().proof_bytes())
                {
                    return Err(UnitPreparationError::InputBound);
                }
                if body.outputs().outputs().iter().any(|o| {
                    o.envelope().payload().len() as u128
                        > u128::from(parent.state().policy().limits().output_payload_bytes())
                }) {
                    return Err(UnitPreparationError::InputBound);
                }
                let anchor = resolve_anchor(parent, body.inputs().anchor())?;
                if anchor.network_id() != body.context().network_id() {
                    return Err(UnitPreparationError::Integrity);
                }
                contexts.push(context);
                anchors.push(Some(anchor));
            }
            TransactionEnvelope::RewardWithdrawal(e) => {
                let body = e.body();
                let context = recognize(TransactionKind::RewardWithdrawal, body.context())?;
                if body.encoded_len(context.body_limits())? as u128
                    > u128::from(parent.state().policy().limits().body_bytes())
                    || e.proof().byte_len() as u128
                        > u128::from(parent.state().policy().limits().proof_bytes())
                {
                    return Err(UnitPreparationError::InputBound);
                }
                if body.output().envelope().payload().len() as u128
                    > u128::from(parent.state().policy().limits().output_payload_bytes())
                {
                    return Err(UnitPreparationError::InputBound);
                }
                require_authority(parent, body)?;
                contexts.push(context);
                anchors.push(None);
            }
        }
    }
    Ok(UnitDependencies {
        contexts,
        anchors,
        compatibility: Compatibility::capture(parent)?,
    })
}

/// Registry and registered-authority composition tests.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::{payment_body, trusted_manifest};
    use crate::validate_bootstrap;
    use houseki_types::{
        Amount, RewardAccountId, RewardWithdrawalBody, TransactionKind, WithdrawalNonce,
    };

    /// Recognition retains the exact body claim even when policy does not activate it.
    #[test]
    fn registry_recognition_does_not_activate() {
        let body = payment_body(1, 1);
        let context = recognize(TransactionKind::Payment, body.context()).unwrap();
        assert_eq!(context.expected(), body.context());
        let mut policy = crate::ExecutionPolicy::development().unwrap();
        policy.payment_profiles.clear();
        assert!(!policy.activates(TransactionKind::Payment, body.context()));
        assert!(recognize(TransactionKind::RewardWithdrawal, body.context()).is_err());
    }

    /// A body-selected key never substitutes for the independently registered source authority.
    #[test]
    fn withdrawal_authority_matches_registered_account() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let body = payment_body(1, 1);
        let context = houseki_types::TransactionContext::new(
            parent.state().network(),
            body.context().protocol_version(),
            houseki_types::ProofProfileId::new(0xffff0007),
            body.context().fee_schedule_id(),
            body.context().validity_checkpoint_range(),
        );
        let (id, account) = parent.state().accounts().next().unwrap();
        let withdrawal = RewardWithdrawalBody::new(
            context,
            RewardAccountId::from_bytes(*id),
            account.withdrawal_authority().clone(),
            WithdrawalNonce::new(0),
            Amount::from_atoms(3).unwrap(),
            Amount::from_atoms(1).unwrap(),
            body.outputs().outputs()[0].clone(),
        )
        .unwrap();
        require_authority(&parent, &withdrawal).unwrap();
        let bad = RewardWithdrawalBody::new(
            context,
            RewardAccountId::from_bytes([0; 64]),
            account.withdrawal_authority().clone(),
            WithdrawalNonce::new(0),
            Amount::from_atoms(3).unwrap(),
            Amount::from_atoms(1).unwrap(),
            body.outputs().outputs()[0].clone(),
        )
        .unwrap();
        assert!(require_authority(&parent, &bad).is_err());
    }
    /// Parent-selected lower byte caps are enforced before actual cryptographic work.
    #[test]
    fn parent_component_bounds_are_rechecked() {
        let mut m = trusted_manifest();
        m.policy.limits.body_bytes = 1;
        m.expected_state_commitment = crate::StateCommitment::from_bytes(
            houseki_crypto::ledger_reference_state(
                &crate::encode_snapshot(
                    &crate::SnapshotRecord::from_state(m.clone().candidate().unwrap().state())
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let base = crate::validate_bootstrap(m.clone())
            .unwrap()
            .into_snapshot();
        let occurrence = crate::test_support::execution::payment(
            base.state(),
            0,
            10,
            houseki_types::ValidatorId::from_bytes([5; 64]),
        );
        let (parent, manifest, raw) =
            crate::test_support::fixture_source_for(m, vec![vec![occurrence]]);
        let unit = crate::FixtureOrderVerifier::new(manifest, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();
        assert!(matches!(
            resolve_dependencies(&parent, &unit),
            Err(UnitPreparationError::InputBound)
        ));
    }
}
