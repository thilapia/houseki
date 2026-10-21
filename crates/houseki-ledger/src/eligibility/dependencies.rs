//! Exact contexts and authenticated descriptors retained by unit authorization.

use super::{
    anchor::resolve_anchor,
    compatibility::Compatibility,
    context::{recognize, require_authority},
};
use crate::{ParentSnapshot, UnitPreparationError, VerifiedOrderUnit};
use houseki_proofs::ProofContext;
use houseki_types::{NoteTreeAnchor, TransactionEnvelope, TransactionKind};

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

/// Parent resource bounds applied before native cryptographic verification.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::trusted_manifest;

    /// Parent selected lower byte caps are enforced before actual cryptographic work.
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
        let occurrence = crate::test_support::payment(
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
