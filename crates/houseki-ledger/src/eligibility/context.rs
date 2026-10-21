//! Immutable recognition dependencies distinct from checkpoint activation.

use crate::{ParentSnapshot, UnitPreparationError};
use houseki_crypto::MlDsa87VerificationKey;
use houseki_proofs::ProofContext;
use houseki_types::{RewardWithdrawalBody, TransactionContext, TransactionKind};

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

/// Checks closed registration and network bound authority without consulting balance or
/// nonce.
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

/// Registry and registered authority composition tests.
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

    /// A body selected key never substitutes for the independently registered source
    /// authority.
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
}
