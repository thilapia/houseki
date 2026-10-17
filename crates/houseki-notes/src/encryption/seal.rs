//! Encryption of canonical private openings after matching the selected public output.

use houseki_crypto::{
    CryptoSuite, NoteEncryptionContext, NoteEncryptionContextError, PaymentEncryptionCore,
};
use houseki_types::NoteOutput;

use super::NoteOutputEncryptionError;
use crate::{NoteFormat, NoteOpening, NoteRecipient};

/// Matches an opening to one payment output and encrypts its canonical private record.
///
/// The selected commitment and suite come from the actual core output, with the complete index
/// preserved during checked host conversion and duplicate commitments retaining distinct slots.
///
/// The expected recipient must belong to the core's network and exactly match the opening's
/// retained snapshot, including declared ownership and the full validated KEM public key.
///
/// Compatible immutable format and suite rules select commitment derivation, which borrows
/// original private material and derives recipient binding internally through crypto.
///
/// After commitment agreement, this operation constructs the output context from the same core,
/// index and recipient key, then retains the canonical plaintext in zeroizing storage through
/// crypto's complete sealing operation, including failure and unwinding.
///
/// Crypto supplies fresh system randomness for the encapsulation and nonce, returning a V1
/// payload of 84 bytes for the 52 byte private record without padding.
///
/// The inclusive `max_payload_bytes` limit covers that payload and excludes the separate
/// encapsulation, while each successful context construction traverses the complete core.
///
/// Callers enforce active rules, counts, total bytes and work limits and assemble the complete
/// body without changing any core field, suite or output order.
///
/// Before authorization, rebuild and compare its projected core by typed fields and digest,
/// then separately bind the complete encrypted body into authorization.
///
/// The returned output does not establish value conservation, membership, spending authority
/// or transaction validity, and the recipient must authenticate and validate recovery.
///
/// # Errors
///
/// Checks the index before network agreement, complete recipient agreement and commitment
/// derivation and matching, returning the corresponding [`NoteOutputEncryptionError`].
///
/// Core context construction and bounded sealing follow, retaining original crypto errors
/// as sources without private values or a partial output.
pub fn encrypt_payment_output(
    core: &PaymentEncryptionCore,
    output_index: u64,
    recipient: &NoteRecipient,
    opening: &NoteOpening,
    max_payload_bytes: usize,
) -> Result<NoteOutput, NoteOutputEncryptionError> {
    let (commitment, suite) = usize::try_from(output_index)
        .ok()
        .and_then(|index| core.outputs().get(index))
        .copied()
        .ok_or(NoteEncryptionContextError::OutputIndexOutOfBounds {
            index: output_index,
            output_count: core.outputs().len(),
        })?;

    if recipient.context().network_id() != core.context().network_id() {
        return Err(NoteOutputEncryptionError::NetworkMismatch);
    }
    if opening.recipient() != recipient {
        return Err(NoteOutputEncryptionError::RecipientMismatch);
    }

    // Require explicit compatibility decisions if any supported format or suite is added.
    match (opening.format(), recipient.suite(), suite) {
        (NoteFormat::V1, CryptoSuite::V1, CryptoSuite::V1) => {}
    }
    if opening.commitment()? != commitment {
        return Err(NoteOutputEncryptionError::CommitmentMismatch);
    }

    let context =
        NoteEncryptionContext::for_payment(core, output_index, recipient.kem_public_key())?;
    let plaintext = opening.encode_plaintext();
    let envelope = context.seal(&plaintext[..], max_payload_bytes)?;

    Ok(NoteOutput::new(commitment, envelope))
}

/// Delivery, complete recipient agreement, selection precedence and transaction binding.
#[cfg(test)]
mod tests {
    use std::error::Error;

    use houseki_crypto::{
        CryptoSuite, MlKem1024DecapsulationKey, NoteDecryptionError, NoteEncryptionContext,
        NoteEncryptionContextError, NoteEncryptionError, PaymentEncryptionCore,
    };
    use houseki_types::{
        AddressContext, AddressFormatVersion, Amount, CheckpointSequence, FeeScheduleId, NetworkId,
        NoteCommitment, NoteRoot, Nullifier, OwnershipCommitment, PaymentBody, PaymentCountLimits,
        PaymentInputs, PaymentOutputs, ProofProfileId, ProtocolVersion, RecipientDescriptor,
        TransactionContext, ValidityCheckpointRange,
    };
    use zeroize::Zeroizing;

    use crate::{
        NoteBlinding, NoteFormat, NoteOpening, NoteOutputEncryptionError, NoteRecipient,
        encrypt_payment_output, payment_encryption_core,
    };

    /// Builds the declared payment context with distinct full identifiers and checkpoint bounds.
    fn context() -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([7; 64]),
            ProtocolVersion::new(0x0100_0002),
            ProofProfileId::new(0x0200_0003),
            FeeScheduleId::new(0x0300_0004),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        )
    }

    /// Supplies limits for two distinct inputs and three ordered outputs.
    fn limits() -> PaymentCountLimits {
        PaymentCountLimits::new(2, 3).unwrap()
    }

    /// Validates a recipient from an actual paired KEM key and declared ownership fixture.
    fn recipient(key: &MlKem1024DecapsulationKey, ownership: [u8; 64]) -> NoteRecipient {
        let network = context().network_id();
        NoteRecipient::validate(
            &RecipientDescriptor::new(
                AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
                OwnershipCommitment::from_bytes(ownership),
                key.encapsulation_key().to_encoded(),
            ),
            network,
        )
        .unwrap()
    }

    /// Retains synthetic private material through the same checked constructor used by senders.
    fn opening(recipient: &NoteRecipient, atoms: u128, blinding: u8) -> NoteOpening {
        NoteOpening::new(
            NoteFormat::V1,
            recipient,
            Amount::from_atoms(atoms).unwrap(),
            NoteBlinding::from_bytes(&[blinding; 32]),
        )
        .unwrap()
    }

    /// Builds the complete core with a selectable output list and separate public fee.
    fn core(outputs: Vec<(NoteCommitment, CryptoSuite)>) -> PaymentEncryptionCore {
        PaymentEncryptionCore::new(
            context(),
            PaymentInputs::new(
                NoteRoot::from_bytes([8; 64]),
                vec![
                    Nullifier::from_bytes([9; 64]),
                    Nullifier::from_bytes([2; 64]),
                ],
                limits(),
            )
            .unwrap(),
            outputs,
            Amount::from_atoms(17).unwrap(),
            limits(),
        )
        .unwrap()
    }

    /// Assembles the specified V1 plaintext independently of the opening codec.
    fn plaintext(atoms: u128, blinding: u8) -> Zeroizing<[u8; 52]> {
        let mut expected = Zeroizing::new([0; 52]);
        expected[0] = 1;
        expected[4..20].copy_from_slice(&atoms.to_le_bytes());
        expected[20..].fill(blinding);
        expected
    }

    /// Checks complete body reconstruction and exact private delivery for distinct recipients.
    #[test]
    fn payment_delivery_preserves_canonical_openings_and_sender_core() {
        let first_key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let second_key = MlKem1024DecapsulationKey::from_seed(&[12; 64]);
        let first_recipient = recipient(&first_key, [13; 64]);
        let second_recipient = recipient(&second_key, [14; 64]);
        for atoms in [1, (1_u128 << 64) + 3, Amount::MAX_ATOMS] {
            let first = opening(&first_recipient, atoms, 0xa5);
            let second = opening(&second_recipient, 19, 0x5a);
            let core = core(vec![
                (first.commitment().unwrap(), CryptoSuite::V1),
                (second.commitment().unwrap(), CryptoSuite::V1),
                (first.commitment().unwrap(), CryptoSuite::V1),
            ]);
            let mut outputs = Vec::new();
            for (index, recipient, opening) in [
                (0, &first_recipient, &first),
                (1, &second_recipient, &second),
                (2, &first_recipient, &first),
            ] {
                let output = encrypt_payment_output(&core, index, recipient, opening, 84).unwrap();
                assert_eq!(output.commitment(), core.outputs()[index as usize].0);
                assert_eq!(output.envelope().payload_len(), 84);
                assert_eq!(&output.envelope().payload()[..4], &[1, 0, 0, 0]);
                outputs.push(output);
            }
            let body = PaymentBody::new(
                core.context(),
                core.inputs().clone(),
                PaymentOutputs::new(outputs, limits()).unwrap(),
                core.public_fee(),
                limits(),
            )
            .unwrap();
            let rebuilt = payment_encryption_core(&body, limits(), 84).unwrap();

            assert_eq!(rebuilt, core);
            assert_eq!(rebuilt.digest().unwrap(), core.digest().unwrap());
            for (index, key, recipient, atoms, blinding) in [
                (0, &first_key, &first_recipient, atoms, 0xa5),
                (1, &second_key, &second_recipient, 19, 0x5a),
                (2, &first_key, &first_recipient, atoms, 0xa5),
            ] {
                let recovered =
                    NoteEncryptionContext::for_payment(&rebuilt, index, recipient.kem_public_key())
                        .unwrap()
                        .open(body.outputs().outputs()[index as usize].envelope(), key, 84)
                        .unwrap();
                assert_eq!(recovered.as_slice(), &plaintext(atoms, blinding)[..]);
            }
            assert_eq!(first.amount().atoms(), atoms);
            assert_eq!(&first.encode_plaintext()[..], &plaintext(atoms, 0xa5)[..]);
        }
    }

    /// Checks that full indices fail before network, recipient, commitment or payload errors.
    #[test]
    fn invalid_indices_preserve_all_bits_before_other_checks() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let opening = opening(&recipient, 1, 0xa5);
        let core = core(vec![(NoteCommitment::from_bytes([0; 64]), CryptoSuite::V1)]);
        let mut bytes = recipient.to_bytes();
        bytes[4] ^= 1;
        let wrong_network = NoteRecipient::from_bytes(
            &bytes,
            NetworkId::from_bytes(std::array::from_fn(|i| if i == 0 { 6 } else { 7 })),
        )
        .unwrap();

        for index in [1, 256, 65_536, 1_u64 << 32, u64::MAX] {
            let error =
                encrypt_payment_output(&core, index, &wrong_network, &opening, 0).unwrap_err();
            assert!(matches!(
                &error,
                NoteOutputEncryptionError::Context(
                    NoteEncryptionContextError::OutputIndexOutOfBounds {
                        index: supplied,
                        output_count: 1,
                    }
                ) if *supplied == index
            ));
            assert!(error.source().unwrap().is::<NoteEncryptionContextError>());
        }
    }

    /// Checks every network byte before an opening or payload mismatch can mask it.
    #[test]
    fn network_mismatch_precedes_recipient_commitment_and_payload_checks() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let opening = opening(&recipient, 1, 0xa5);
        let core = core(vec![(NoteCommitment::from_bytes([0; 64]), CryptoSuite::V1)]);

        for index in 0..64 {
            let mut network = [7; 64];
            network[index] ^= 1;
            let mut bytes = recipient.to_bytes();
            bytes[4..68].copy_from_slice(&network);
            let changed =
                NoteRecipient::from_bytes(&bytes, NetworkId::from_bytes(network)).unwrap();
            assert!(matches!(
                encrypt_payment_output(&core, 0, &changed, &opening, 0),
                Err(NoteOutputEncryptionError::NetworkMismatch)
            ));
        }
    }

    /// Checks the expected ownership, complete key and opening network before commitment matching.
    #[test]
    fn recipient_agreement_uses_the_complete_retained_snapshot() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let original = opening(&recipient, 1, 0xa5);
        let core = core(vec![(original.commitment().unwrap(), CryptoSuite::V1)]);

        for index in (72..136).chain([136 + 1536, 136 + 1567]) {
            let mut bytes = recipient.to_bytes();
            bytes[index] ^= 1;
            let changed = NoteRecipient::from_bytes(&bytes, context().network_id()).unwrap();
            assert!(matches!(
                encrypt_payment_output(&core, 0, &changed, &original, 0),
                Err(NoteOutputEncryptionError::RecipientMismatch)
            ));
        }
        let other_key = MlKem1024DecapsulationKey::from_seed(&[12; 64]);
        let other = self::recipient(&other_key, [13; 64]);
        assert!(matches!(
            encrypt_payment_output(&core, 0, &other, &original, 0),
            Err(NoteOutputEncryptionError::RecipientMismatch)
        ));
        let mut bytes = recipient.to_bytes();
        bytes[67] ^= 1;
        let mut network = [7; 64];
        network[63] ^= 1;
        let changed = NoteRecipient::from_bytes(&bytes, NetworkId::from_bytes(network)).unwrap();
        let changed_opening = opening(&changed, 1, 0xa5);
        assert!(matches!(
            encrypt_payment_output(&core, 0, &recipient, &changed_opening, 0),
            Err(NoteOutputEncryptionError::RecipientMismatch)
        ));
    }

    /// Checks all selected commitment bytes and changed private material before sealing.
    #[test]
    fn commitment_matching_precedes_payload_checks() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let original = opening(&recipient, 1, 0xa5);
        let commitment = original.commitment().unwrap();

        for index in 0..64 {
            let mut bytes = *commitment.as_bytes();
            bytes[index] ^= 1;
            let core = core(vec![(NoteCommitment::from_bytes(bytes), CryptoSuite::V1)]);
            assert!(matches!(
                encrypt_payment_output(&core, 0, &recipient, &original, 0),
                Err(NoteOutputEncryptionError::CommitmentMismatch)
            ));
        }
        let core = core(vec![(commitment, CryptoSuite::V1)]);
        for changed in [opening(&recipient, 2, 0xa5), opening(&recipient, 1, 0xa4)] {
            assert!(matches!(
                encrypt_payment_output(&core, 0, &recipient, &changed, 0),
                Err(NoteOutputEncryptionError::CommitmentMismatch)
            ));
        }
    }

    /// Checks inclusive payload bounds and unchanged private storage across failure and success.
    #[test]
    fn payload_limits_preserve_crypto_sources_and_borrowed_openings() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let opening = opening(&recipient, 1_u128 << 64, 0xa5);
        let core = core(vec![(opening.commitment().unwrap(), CryptoSuite::V1)]);

        for maximum in [0, 32, 83] {
            let error =
                encrypt_payment_output(&core, 0, &recipient, &opening, maximum).unwrap_err();
            assert!(matches!(
                &error,
                NoteOutputEncryptionError::Encryption(
                    NoteEncryptionError::PayloadLengthExceedsLimit { actual: 84, maximum: bound }
                ) if *bound == maximum
            ));
            assert!(error.source().unwrap().is::<NoteEncryptionError>());
            assert_eq!(
                &opening.encode_plaintext()[..],
                &plaintext(1_u128 << 64, 0xa5)[..]
            );
        }
        for maximum in [84, 85, usize::MAX] {
            let output = encrypt_payment_output(&core, 0, &recipient, &opening, maximum).unwrap();
            let context =
                NoteEncryptionContext::for_payment(&core, 0, recipient.kem_public_key()).unwrap();
            assert_eq!(output.envelope().payload_len(), 84);
            assert_eq!(
                context
                    .open(output.envelope(), &key, 84)
                    .unwrap()
                    .as_slice(),
                &plaintext(1_u128 << 64, 0xa5)[..]
            );
        }
        assert_eq!(
            &opening.encode_plaintext()[..],
            &plaintext(1_u128 << 64, 0xa5)[..]
        );
    }

    /// Checks duplicate slot separation and complete core binding through authenticated recovery.
    #[test]
    fn encrypted_outputs_authenticate_only_the_selected_slot_and_complete_core() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let opening = opening(&recipient, 1, 0xa5);
        let commitment = opening.commitment().unwrap();
        let core = core(vec![
            (commitment, CryptoSuite::V1),
            (NoteCommitment::from_bytes([0; 64]), CryptoSuite::V1),
            (commitment, CryptoSuite::V1),
        ]);
        let output = encrypt_payment_output(&core, 0, &recipient, &opening, 84).unwrap();
        let duplicate =
            NoteEncryptionContext::for_payment(&core, 2, recipient.kem_public_key()).unwrap();
        assert!(matches!(
            duplicate.open(output.envelope(), &key, 84),
            Err(NoteDecryptionError::AuthenticationFailed)
        ));

        for change in 0..13 {
            let (original, inputs, mut outputs, mut fee) = core.clone().into_parts();
            let mut network = original.network_id();
            let mut protocol = original.protocol_version();
            let mut proof = original.proof_profile_id();
            let mut schedule = original.fee_schedule_id();
            let mut start = CheckpointSequence::new(5);
            let mut end = CheckpointSequence::new(8);
            let (mut anchor, mut nullifiers) = inputs.into_parts();
            match change {
                0 => network = NetworkId::from_bytes([6; 64]),
                1 => protocol = ProtocolVersion::new(0x0100_0003),
                2 => proof = ProofProfileId::new(0x0200_0002),
                3 => schedule = FeeScheduleId::new(0x0300_0005),
                4 => start = CheckpointSequence::new(4),
                5 => end = CheckpointSequence::new(9),
                6 => anchor = NoteRoot::from_bytes([10; 64]),
                7 => nullifiers[0] = Nullifier::from_bytes([10; 64]),
                8 => nullifiers.swap(0, 1),
                9 => fee = Amount::from_atoms(18).unwrap(),
                10 => outputs[1].0 = NoteCommitment::from_bytes([1; 64]),
                11 => outputs.swap(1, 2),
                12 => {
                    outputs.pop();
                }
                _ => unreachable!(),
            }
            let context = TransactionContext::new(
                network,
                protocol,
                proof,
                schedule,
                ValidityCheckpointRange::new(start, end).unwrap(),
            );
            let changed = PaymentEncryptionCore::new(
                context,
                PaymentInputs::new(anchor, nullifiers, limits()).unwrap(),
                outputs,
                fee,
                limits(),
            )
            .unwrap();
            let context =
                NoteEncryptionContext::for_payment(&changed, 0, recipient.kem_public_key())
                    .unwrap();

            assert!(
                matches!(
                    context.open(output.envelope(), &key, 84),
                    Err(NoteDecryptionError::AuthenticationFailed)
                ),
                "core mutation {change} unexpectedly authenticated"
            );
        }
    }
}
