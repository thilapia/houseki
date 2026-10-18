//! Native ordered payment equations with concrete spends and exact private conservation.

mod error;

pub use error::PaymentRelationError;

use crate::{NoteOpening, SpendWitness};
use houseki_types::{NoteTreeAnchor, PaymentBody, PaymentCountLimits};

/// Checks actual ordered spends, output commitments and exact private amount conservation.
///
/// Every input requires linked ownership and concrete occupied membership under the exact body
/// anchor, while every positive output opening must match its actual ordered commitment.
///
/// Repeated output references count at every slot and the separate public fee is added once.
///
/// Private totals remain guarded with sufficient width for all representable host list counts.
///
/// The relation does not authenticate ciphertext delivery, anchor finality or unspentness, resolve
/// active fee policy or verify a proof or a knowledge argument.
///
/// Proof consumers separately bind the complete canonical body, including its encrypted envelopes.
///
/// # Errors
///
/// Checks active counts, exact witness counts and selected anchor before input relations, then
/// output rules and exact conservation, returning no partial verification evidence or totals.
pub fn check_payment(
    body: &PaymentBody,
    anchor: &NoteTreeAnchor,
    inputs: &[SpendWitness<'_>],
    outputs: &[&NoteOpening],
    limits: PaymentCountLimits,
) -> Result<(), PaymentRelationError> {
    limits.validate_shape(body.shape())?;

    if inputs.len() != body.inputs().input_count() {
        return Err(PaymentRelationError::InputCountMismatch);
    }

    if outputs.len() != body.outputs().output_count() {
        return Err(PaymentRelationError::OutputCountMismatch);
    }

    if body.context().network_id() != anchor.network_id() || body.inputs().anchor() != anchor.root()
    {
        return Err(PaymentRelationError::AnchorMismatch);
    }

    let mut seen = std::collections::HashSet::new();
    seen.try_reserve(body.inputs().input_count())
        .map_err(|_| PaymentRelationError::AllocationFailed)?;
    for marker in body.inputs().nullifiers() {
        if !seen.insert(marker) {
            return Err(PaymentRelationError::DuplicateNullifier);
        }
    }

    for (input_index, (marker, witness)) in
        body.inputs().nullifiers().iter().zip(inputs).enumerate()
    {
        crate::check_spend(anchor, *marker, witness).map_err(|source| {
            PaymentRelationError::Spend {
                input_index,
                source,
            }
        })?;
    }

    for (output_index, (output, opening)) in
        body.outputs().outputs().iter().zip(outputs).enumerate()
    {
        match (opening.format(), opening.recipient().suite()) {
            (crate::NoteFormat::V1, houseki_crypto::CryptoSuite::V1) => {}
        }

        if opening.recipient().context().network_id() != body.context().network_id() {
            return Err(PaymentRelationError::OutputNetworkMismatch { output_index });
        }

        if opening.commitment()? != output.commitment() {
            return Err(PaymentRelationError::OutputCommitmentMismatch { output_index });
        }
    }

    let balanced = crate::accumulation::amounts_balance(
        inputs.iter().map(|input| input.opening.amount()),
        outputs.iter().map(|opening| opening.amount()),
        &body.public_fee(),
    )
    .map_err(|_| PaymentRelationError::ArithmeticOverflow)?;
    if !balanced {
        return Err(PaymentRelationError::ConservationMismatch);
    }

    Ok(())
}

/// Concrete input paths, exact totals and complete receive to spend integration.
#[cfg(test)]
mod tests {
    use crate::{
        NoteBlinding, NoteFormat, NoteOpening, NoteRecipient, PaymentRelationError, SpendWitness,
        check_payment, check_spend, check_withdrawal_output, derive_nullifier,
        encrypt_payment_output, encrypt_withdrawal_output, recover_payment_output,
        recover_withdrawal_output,
    };
    use houseki_crypto::{
        CryptoSuite, MlDsa87SigningKey, MlKem1024DecapsulationKey, NullifierKey,
        PaymentEncryptionCore, RewardWithdrawalEncryptionCore, SpendingKey, payment_transaction_id,
    };
    use houseki_state::NoteTree;
    use houseki_types::*;

    /// Permits real four input payments and up to three ordinary output slots.
    fn limits() -> PaymentCountLimits {
        PaymentCountLimits::new(4, 3).unwrap()
    }

    /// Binds all fixture operations to one complete public context.
    fn context() -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([7; 64]),
            ProtocolVersion::new(2),
            ProofProfileId::new(3),
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        )
    }

    /// Creates the actual linked public recipient from independently owned fixture keys.
    fn recipient(
        spending: &SpendingKey,
        nullifier: &NullifierKey,
        key: &MlKem1024DecapsulationKey,
    ) -> NoteRecipient {
        let network = context().network_id();
        NoteRecipient::validate(
            &RecipientDescriptor::new(
                AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
                spending.ownership_commitment(network, nullifier).unwrap(),
                key.encapsulation_key().to_encoded(),
            ),
            network,
        )
        .unwrap()
    }

    /// Builds a positive protected synthetic ordinary opening without private byte export.
    fn opening(recipient: &NoteRecipient, amount: u128, rho: u8) -> NoteOpening {
        NoteOpening::new(
            NoteFormat::V1,
            recipient,
            Amount::from_atoms(amount).unwrap(),
            NoteBlinding::from_bytes(&[rho; 32]),
        )
        .unwrap()
    }

    /// Leaves opaque delivery intentionally invalid while isolating the native mathematical relation.
    fn body(
        anchor: &NoteTreeAnchor,
        markers: Vec<Nullifier>,
        outputs: &[&NoteOpening],
        fee: u128,
    ) -> PaymentBody {
        let outputs = outputs
            .iter()
            .map(|opening| {
                NoteOutput::new(
                    opening.commitment().unwrap(),
                    EncryptedNoteEnvelope::new(
                        EncodedMlKem1024Ciphertext::from_bytes([0; 1568]),
                        Vec::new(),
                        0,
                    )
                    .unwrap(),
                )
            })
            .collect();

        PaymentBody::new(
            context(),
            PaymentInputs::new(anchor.root(), markers, limits()).unwrap(),
            PaymentOutputs::new(outputs, limits()).unwrap(),
            Amount::from_atoms(fee).unwrap(),
            limits(),
        )
        .unwrap()
    }

    /// Counts repeated outputs and distinct inserted duplicate inputs exactly, including totals
    /// above the amount cap.
    #[test]
    fn payment_conservation_counts_every_occurrence_and_the_fee_once() {
        let spending = SpendingKey::from_bytes(&[0xa7; 32]);
        let nullifier = NullifierKey::from_bytes(&[0x59; 32]);
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&spending, &nullifier, &key);

        let input = opening(&recipient, Amount::MAX_ATOMS, 0xa5);
        let output = opening(&recipient, Amount::MAX_ATOMS, 0x5a);

        let mut tree = NoteTree::new(context().network_id()).unwrap();
        let first = tree.append(input.commitment().unwrap()).unwrap();
        let second = tree.append(input.commitment().unwrap()).unwrap();

        let first_path = tree.witness(&first).unwrap();
        let second_path = tree.witness(&second).unwrap();
        let anchor = tree.anchor();
        let markers = vec![
            derive_nullifier(&input, &nullifier, &first).unwrap(),
            derive_nullifier(&input, &nullifier, &second).unwrap(),
        ];
        let inputs = [
            SpendWitness::new(&input, &spending, &nullifier, &first_path),
            SpendWitness::new(&input, &spending, &nullifier, &second_path),
        ];

        let repeated = body(&anchor, markers.clone(), &[&output, &output], 0);
        check_payment(&repeated, &anchor, &inputs, &[&output, &output], limits()).unwrap();

        let reversed = [
            SpendWitness::new(&input, &spending, &nullifier, &second_path),
            SpendWitness::new(&input, &spending, &nullifier, &first_path),
        ];

        assert!(matches!(
            check_payment(&repeated, &anchor, &reversed, &[&output, &output], limits()),
            Err(PaymentRelationError::Spend { input_index: 0, .. })
        ));

        let fee = body(&anchor, markers.clone(), &[&output], Amount::MAX_ATOMS);
        check_payment(&fee, &anchor, &inputs, &[&output], limits()).unwrap();

        let missing = body(&anchor, markers.clone(), &[&output], 0);

        assert!(matches!(
            check_payment(&missing, &anchor, &inputs, &[&output], limits()),
            Err(PaymentRelationError::ConservationMismatch)
        ));

        let extra_fee = body(&anchor, markers, &[&output, &output], 1);

        assert!(matches!(
            check_payment(&extra_fee, &anchor, &inputs, &[&output, &output], limits()),
            Err(PaymentRelationError::ConservationMismatch)
        ));
    }

    /// Counts four distinct note instances and both repeated outputs without a one-note total cap.
    #[test]
    fn four_input_payment_conserves_repeated_outputs_and_separate_fee() {
        let spending = SpendingKey::from_bytes(&[0xa7; 32]);
        let nullifier = NullifierKey::from_bytes(&[0x59; 32]);
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&spending, &nullifier, &key);
        for input_amount in [Amount::MAX_ATOMS / 2, Amount::MAX_ATOMS] {
            let input = opening(&recipient, input_amount, 0xa5);
            let output = opening(&recipient, Amount::MAX_ATOMS, 0x5a);
            let mut tree = NoteTree::new(context().network_id()).unwrap();
            let positions: Vec<_> = (0..4)
                .map(|_| tree.append(input.commitment().unwrap()).unwrap())
                .collect();
            let paths: Vec<_> = positions
                .iter()
                .map(|position| tree.witness(position).unwrap())
                .collect();
            let inputs: Vec<_> = paths
                .iter()
                .map(|path| SpendWitness::new(&input, &spending, &nullifier, path))
                .collect();
            let markers: Vec<_> = positions
                .iter()
                .map(|position| derive_nullifier(&input, &nullifier, position).unwrap())
                .collect();
            let anchor = tree.anchor();
            let outputs = [&output, &output];
            let counts = PaymentCountLimits::new(4, 2).unwrap();
            let fee = if input_amount == Amount::MAX_ATOMS {
                Amount::MAX_ATOMS
            } else {
                0
            };
            let payment = body(&anchor, markers.clone(), &outputs, fee);
            let result = check_payment(&payment, &anchor, &inputs, &outputs, counts);
            if input_amount == Amount::MAX_ATOMS {
                assert!(matches!(
                    result,
                    Err(PaymentRelationError::ConservationMismatch)
                ));
            } else {
                result.unwrap();
                let payment = body(&anchor, markers.clone(), &[&output], Amount::MAX_ATOMS);

                check_payment(&payment, &anchor, &inputs, &[&output], counts).unwrap();

                let payment = body(&anchor, markers, &outputs, 1);

                assert!(matches!(
                    check_payment(&payment, &anchor, &inputs, &outputs, counts),
                    Err(PaymentRelationError::ConservationMismatch)
                ));
            }
        }
    }

    /// Requires exact counts, anchor, input order and output correspondence before conservation.
    #[test]
    fn payment_relation_rejects_mismatched_statement_and_witness_lists() {
        let spending = SpendingKey::from_bytes(&[0xa7; 32]);
        let nullifier = NullifierKey::from_bytes(&[0x59; 32]);
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&spending, &nullifier, &key);

        let input = opening(&recipient, 23, 0xa5);
        let first_output = opening(&recipient, 18, 0x5a);
        let second_output = opening(&recipient, 2, 0x5b);

        let mut tree = NoteTree::new(context().network_id()).unwrap();
        let position = tree.append(input.commitment().unwrap()).unwrap();
        let path = tree.witness(&position).unwrap();
        let anchor = tree.anchor();
        let marker = derive_nullifier(&input, &nullifier, &position).unwrap();
        let inputs = [SpendWitness::new(&input, &spending, &nullifier, &path)];

        let body = body(&anchor, vec![marker], &[&first_output, &second_output], 3);
        check_payment(
            &body,
            &anchor,
            &inputs,
            &[&first_output, &second_output],
            limits(),
        )
        .unwrap();

        assert!(matches!(
            check_payment(
                &body,
                &anchor,
                &[],
                &[&first_output, &second_output],
                limits()
            ),
            Err(PaymentRelationError::InputCountMismatch)
        ));
        assert!(matches!(
            check_payment(&body, &anchor, &inputs, &[&first_output], limits()),
            Err(PaymentRelationError::OutputCountMismatch)
        ));
        assert!(matches!(
            check_payment(
                &body,
                &anchor,
                &inputs,
                &[&second_output, &first_output],
                limits()
            ),
            Err(PaymentRelationError::OutputCommitmentMismatch { output_index: 0 })
        ));

        let other_network = NetworkId::from_bytes([6; 64]);
        let other_recipient = NoteRecipient::validate(
            &RecipientDescriptor::new(
                AddressContext::new(
                    other_network,
                    AddressFormatVersion::new(1),
                    CryptoSuite::V1.id(),
                ),
                spending
                    .ownership_commitment(other_network, &nullifier)
                    .unwrap(),
                key.encapsulation_key().to_encoded(),
            ),
            other_network,
        )
        .unwrap();

        let other_output = opening(&other_recipient, 20, 0x5a);
        let other_body = self::body(&anchor, vec![marker], &[&other_output], 3);

        assert!(matches!(
            check_payment(&other_body, &anchor, &inputs, &[&other_output], limits()),
            Err(PaymentRelationError::OutputNetworkMismatch { output_index: 0 })
        ));

        let tight = PaymentCountLimits::new(1, 1).unwrap();

        assert!(matches!(
            check_payment(
                &body,
                &anchor,
                &inputs,
                &[&first_output, &second_output],
                tight
            ),
            Err(PaymentRelationError::Counts(_))
        ));

        let wrong = NoteTreeAnchor::new(
            anchor.network_id(),
            anchor.count(),
            NoteRoot::from_bytes([0; 64]),
        );

        assert!(matches!(
            check_payment(
                &body,
                &wrong,
                &inputs,
                &[&first_output, &second_output],
                limits()
            ),
            Err(PaymentRelationError::AnchorMismatch)
        ));

        let changed = self::body(
            &anchor,
            vec![Nullifier::from_bytes([0; 64])],
            &[&first_output, &second_output],
            3,
        );

        assert!(matches!(
            check_payment(
                &changed,
                &anchor,
                &inputs,
                &[&first_output, &second_output],
                limits()
            ),
            Err(PaymentRelationError::Spend { input_index: 0, .. })
        ));
    }

    /// Receives an actually signed withdrawal, spends its real path and receives and verifies
    /// the next note.
    #[test]
    fn received_outputs_can_be_spent_against_actual_updated_membership() {
        let alice_spending = SpendingKey::from_bytes(&[0xa7; 32]);
        let alice_nullifier = NullifierKey::from_bytes(&[0x59; 32]);
        let alice_kem = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let alice = recipient(&alice_spending, &alice_nullifier, &alice_kem);
        let alice =
            NoteRecipient::from_address(&alice.to_address().unwrap(), context().network_id())
                .unwrap();

        let bob_spending = SpendingKey::from_bytes(&[0xb7; 32]);
        let bob_nullifier = NullifierKey::from_bytes(&[0x69; 32]);
        let bob_kem = MlKem1024DecapsulationKey::from_seed(&[12; 64]);
        let bob = recipient(&bob_spending, &bob_nullifier, &bob_kem);

        let incoming = opening(&alice, 23, 0xa5);
        let authority = MlDsa87SigningKey::from_seed(&[0x79; 32]);
        let public = authority.verification_key();
        let core = RewardWithdrawalEncryptionCore::new(
            context(),
            public.reward_account_id(context().network_id()).unwrap(),
            public.to_encoded(),
            WithdrawalNonce::new(9),
            Amount::from_atoms(23).unwrap(),
            Amount::from_atoms(17).unwrap(),
            (incoming.commitment().unwrap(), CryptoSuite::V1),
        )
        .unwrap();

        let output = encrypt_withdrawal_output(&core, &alice, &incoming, 84).unwrap();
        let withdrawal = RewardWithdrawalBody::new(
            context(),
            core.reward_account_id(),
            public.to_encoded(),
            core.nonce(),
            core.public_amount(),
            core.public_fee(),
            output,
        )
        .unwrap();

        let bytes_limits = BodyCodecLimits::new(limits(), 84, 16384);
        let withdrawal = RewardWithdrawalBody::from_bytes(
            &withdrawal.to_bytes(bytes_limits).unwrap(),
            bytes_limits,
        )
        .unwrap();

        let signature = authority
            .sign_reward_withdrawal(&withdrawal, bytes_limits)
            .unwrap();
        public
            .verify_reward_withdrawal(&withdrawal, &signature, bytes_limits)
            .unwrap();

        let recovered = recover_withdrawal_output(&withdrawal, &alice, &alice_kem, 84).unwrap();
        check_withdrawal_output(&withdrawal, &recovered).unwrap();

        let mut tree = NoteTree::new(context().network_id()).unwrap();
        let original_position = tree.append(recovered.commitment().unwrap()).unwrap();
        let anchor = tree.anchor();
        let membership = tree.witness(&original_position).unwrap();
        let marker =
            derive_nullifier(&recovered, &alice_nullifier, membership.original_position()).unwrap();

        let recipient_note = opening(&bob, 18, 0x5a);
        let change = opening(&alice, 2, 0x5b);
        let core = PaymentEncryptionCore::new(
            context(),
            PaymentInputs::new(anchor.root(), vec![marker], limits()).unwrap(),
            vec![
                (recipient_note.commitment().unwrap(), CryptoSuite::V1),
                (change.commitment().unwrap(), CryptoSuite::V1),
            ],
            Amount::from_atoms(3).unwrap(),
            limits(),
        )
        .unwrap();

        let outputs = vec![
            encrypt_payment_output(&core, 0, &bob, &recipient_note, 84).unwrap(),
            encrypt_payment_output(&core, 1, &alice, &change, 84).unwrap(),
        ];
        let payment = PaymentBody::new(
            context(),
            core.inputs().clone(),
            PaymentOutputs::new(outputs, limits()).unwrap(),
            core.public_fee(),
            limits(),
        )
        .unwrap();

        let payment =
            PaymentBody::from_bytes(&payment.to_bytes(bytes_limits).unwrap(), bytes_limits)
                .unwrap();

        let witnesses = [SpendWitness::new(
            &recovered,
            &alice_spending,
            &alice_nullifier,
            &membership,
        )];

        check_payment(
            &payment,
            &anchor,
            &witnesses,
            &[&recipient_note, &change],
            limits(),
        )
        .unwrap();

        let bob_received =
            recover_payment_output(&payment, 0, &bob, &bob_kem, limits(), 84).unwrap();

        let bob_position = tree
            .append(payment.outputs().outputs()[0].commitment())
            .unwrap();
        tree.append(payment.outputs().outputs()[1].commitment())
            .unwrap();

        let bob_membership = tree.witness(&bob_position).unwrap();
        let bob_marker = derive_nullifier(
            &bob_received,
            &bob_nullifier,
            bob_membership.original_position(),
        )
        .unwrap();

        check_spend(
            &tree.anchor(),
            bob_marker,
            &SpendWitness::new(
                &bob_received,
                &bob_spending,
                &bob_nullifier,
                &bob_membership,
            ),
        )
        .unwrap();

        assert_ne!(marker, bob_marker);

        let (context, inputs, outputs, _) = payment.clone().into_parts();
        let changed = PaymentBody::new(
            context,
            inputs,
            outputs,
            Amount::from_atoms(4).unwrap(),
            limits(),
        )
        .unwrap();

        assert!(matches!(
            check_payment(
                &changed,
                &anchor,
                &witnesses,
                &[&recipient_note, &change],
                limits()
            ),
            Err(PaymentRelationError::ConservationMismatch)
        ));
        assert!(recover_payment_output(&changed, 0, &bob, &bob_kem, limits(), 84).is_err());
        assert_ne!(
            payment_transaction_id(&payment, bytes_limits).unwrap(),
            payment_transaction_id(&changed, bytes_limits).unwrap()
        );
    }
}
