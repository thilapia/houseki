//! Authentication, guarded canonical parsing and commitment agreement for received notes.

use houseki_crypto::{
    MlKem1024DecapsulationKey, NoteDecryptionError, NoteEncryptionContext,
    NoteEncryptionContextError, PaymentEncryptionCoreError,
};
use houseki_types::{PaymentBody, PaymentCountLimits};

use super::{NoteContextError, NoteRecoveryError, payment_encryption_core};
use crate::{NoteOpening, NoteRecipient};

/// Authenticates and validates one payment output before returning its protected opening.
///
/// The complete `u64` index selects an actual body output through checked host conversion,
/// after rechecking input and output counts against the supplied limits.
///
/// Core projection then inspects every public payload in body order, preserving the complete
/// context, anchor, ordered nullifiers, fee and ordered commitment and suite pairs.
///
/// The expected recipient must belong to that network and name the selected output suite,
/// with crypto checking that the supplied private key matches its validated public key.
///
/// An internally constructed payment context authenticates the selected envelope before
/// canonical parsing, retaining crypto's plaintext owner in zeroizing storage through parsing
/// and commitment matching, including error and unwinding.
///
/// Parsing requires the exact supported positive note record and retains the expected recipient,
/// while commitment derivation binds its declared ownership and full validated public key.
///
/// The protected opening is returned only after its recomputed commitment equals the selected
/// published commitment, with no public plaintext parser or intermediate opening returned.
///
/// The inclusive `max_payload_bytes` limit covers each complete public payload and excludes
/// separate encapsulations, while the source body and key remain borrowed and unchanged.
///
/// Projection rechecks counts before allocating its output pairs and copies public core lists,
/// and context construction traverses the complete reconstructed core.
///
/// Callers bound body decoding before allocation and enforce active protocol rules and total
/// byte and work limits, with recovery authenticating only the selected envelope.
///
/// A recovered opening does not establish membership, original insertion position, finality,
/// unspentness, spending authority or transaction validity.
///
/// # Errors
///
/// Checks input counts, output counts and the complete index before inspecting payloads,
/// preserving public projection and context failures as [`NoteRecoveryError`] sources.
///
/// Complete payload projection precedes network and expected suite agreement, with suite or
/// key disagreement and failed authentication retaining crypto's grouped authentication error.
///
/// Malformed authenticated records share [`NoteRecoveryError::InvalidPlaintext`], while
/// commitment framing failures retain their source and disagreement returns
/// [`NoteRecoveryError::CommitmentMismatch`] without private values or a partial opening.
pub fn recover_payment_output(
    body: &PaymentBody,
    output_index: u64,
    recipient: &NoteRecipient,
    key: &MlKem1024DecapsulationKey,
    limits: PaymentCountLimits,
    max_payload_bytes: usize,
) -> Result<NoteOpening, NoteRecoveryError> {
    limits
        .validate_shape(body.shape())
        .map_err(PaymentEncryptionCoreError::from)
        .map_err(NoteContextError::from)?;
    let (index, output) = usize::try_from(output_index)
        .ok()
        .and_then(|index| {
            body.outputs()
                .outputs()
                .get(index)
                .map(|output| (index, output))
        })
        .ok_or(NoteEncryptionContextError::OutputIndexOutOfBounds {
            index: output_index,
            output_count: body.outputs().output_count(),
        })?;

    let core = payment_encryption_core(body, limits, max_payload_bytes)?;
    if recipient.context().network_id() != core.context().network_id() {
        return Err(NoteRecoveryError::NetworkMismatch);
    }
    // Projection preserves every output in order, including this already checked position.
    if core.outputs()[index].1 != recipient.suite() {
        return Err(NoteDecryptionError::AuthenticationFailed.into());
    }

    let context =
        NoteEncryptionContext::for_payment(&core, output_index, recipient.kem_public_key())?;
    let plaintext = context.open(output.envelope(), key, max_payload_bytes)?;
    let opening = NoteOpening::decode_plaintext(&plaintext, recipient)
        .map_err(|_| NoteRecoveryError::InvalidPlaintext)?;
    if opening.commitment()? != output.commitment() {
        return Err(NoteRecoveryError::CommitmentMismatch);
    }

    Ok(opening)
}

/// Exact recovery, bounded selection, authenticated malformed records and adversarial binding.
#[cfg(test)]
mod tests {
    use std::error::Error;

    use houseki_crypto::{
        CryptoSuite, CryptoSuiteError, MlKem1024DecapsulationKey, NoteDecryptionError,
        NoteEncryptionContext, NoteEncryptionContextError, NotePayloadError, PaymentEncryptionCore,
        PaymentEncryptionCoreError,
    };
    use houseki_types::{
        AddressContext, AddressFormatVersion, Amount, CheckpointSequence,
        EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope, FeeScheduleId, NetworkId,
        NoteCommitment, NoteOutput, NoteRoot, Nullifier, OwnershipCommitment, PaymentBody,
        PaymentCountLimits, PaymentCountLimitsError, PaymentInputs, PaymentOutputs, ProofProfileId,
        ProtocolVersion, RecipientDescriptor, TransactionContext, ValidityCheckpointRange,
    };
    use zeroize::Zeroizing;

    use crate::{
        NoteBlinding, NoteContextError, NoteFormat, NoteOpening, NoteRecipient, NoteRecoveryError,
        encrypt_payment_output, recover_payment_output,
    };

    /// Builds the declared context with distinctive complete identifiers and checkpoint bounds.
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

    /// Permits two input nullifiers and up to three ordinary output positions.
    fn limits() -> PaymentCountLimits {
        PaymentCountLimits::new(2, 3).unwrap()
    }

    /// Validates declared ownership and the complete public key from a reproducible paired key.
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

    /// Retains synthetic private material through the checked positive opening constructor.
    fn opening(recipient: &NoteRecipient, atoms: u128, blinding: u8) -> NoteOpening {
        NoteOpening::new(
            NoteFormat::V1,
            recipient,
            Amount::from_atoms(atoms).unwrap(),
            NoteBlinding::from_bytes(&[blinding; 32]),
        )
        .unwrap()
    }

    /// Assembles the independent V1 private record without calling the codec under test.
    fn plaintext(atoms: u128, blinding: u8) -> Zeroizing<[u8; 52]> {
        let mut bytes = Zeroizing::new([0; 52]);
        bytes[0] = 1;
        bytes[4..20].copy_from_slice(&atoms.to_le_bytes());
        bytes[20..].fill(blinding);
        bytes
    }

    /// Builds a core with ordered distinct inputs, declared output pairs and a separate fee.
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

    /// Preserves every declared core field while assembling a completed body from its outputs.
    fn body(core: &PaymentEncryptionCore, outputs: Vec<NoteOutput>) -> PaymentBody {
        PaymentBody::new(
            core.context(),
            core.inputs().clone(),
            PaymentOutputs::new(outputs, limits()).unwrap(),
            core.public_fee(),
            limits(),
        )
        .unwrap()
    }

    /// Delivers three notes including a repeated commitment at distinct output positions.
    fn delivered_body(recipient: &NoteRecipient, atoms: u128) -> (NoteOpening, PaymentBody) {
        let first = opening(recipient, atoms, 0xa5);
        let second = opening(recipient, 19, 0x5a);
        let core = core(vec![
            (first.commitment().unwrap(), CryptoSuite::V1),
            (second.commitment().unwrap(), CryptoSuite::V1),
            (first.commitment().unwrap(), CryptoSuite::V1),
        ]);
        let outputs = [(0, &first), (1, &second), (2, &first)]
            .into_iter()
            .map(|(index, opening)| {
                encrypt_payment_output(&core, index, recipient, opening, 84).unwrap()
            })
            .collect();
        (first, body(&core, outputs))
    }

    /// Replaces encrypted bytes without changing the selected declared commitment or body fields.
    fn replace_envelope(
        original: &PaymentBody,
        index: usize,
        envelope: EncryptedNoteEnvelope,
    ) -> PaymentBody {
        let (context, inputs, outputs, fee) = original.clone().into_parts();
        let mut outputs = outputs.into_outputs();
        outputs[index] = NoteOutput::new(outputs[index].commitment(), envelope);
        PaymentBody::new(
            context,
            inputs,
            PaymentOutputs::new(outputs, limits()).unwrap(),
            fee,
            limits(),
        )
        .unwrap()
    }

    /// Authenticates arbitrary fixture bytes under a sender selected public commitment.
    fn authenticated_body(
        plaintext: &[u8],
        commitment: NoteCommitment,
        recipient: &NoteRecipient,
    ) -> PaymentBody {
        let core = core(vec![(commitment, CryptoSuite::V1)]);
        let context =
            NoteEncryptionContext::for_payment(&core, 0, recipient.kem_public_key()).unwrap();
        let envelope = context.seal(plaintext, 96).unwrap();
        body(&core, vec![NoteOutput::new(commitment, envelope)])
    }

    /// Checks every selected opening, boundary amount and independent retained recipient snapshot.
    #[test]
    fn payment_recovery_returns_exact_guarded_openings_without_changing_the_body() {
        for seed in [11, 12] {
            let key = MlKem1024DecapsulationKey::from_seed(&[seed; 64]);
            let recipient = recipient(&key, [13; 64]);
            for atoms in [1, (1_u128 << 64) + 3, Amount::MAX_ATOMS] {
                let (original, body) = delivered_body(&recipient, atoms);
                let unchanged = body.clone();
                for (index, atoms, blinding) in [(0, atoms, 0xa5), (1, 19, 0x5a), (2, atoms, 0xa5)]
                {
                    let recovered =
                        recover_payment_output(&body, index, &recipient, &key, limits(), 84)
                            .unwrap();
                    assert_eq!(recovered.format(), NoteFormat::V1);
                    assert_eq!(recovered.recipient(), &recipient);
                    assert_eq!(recovered.amount().atoms(), atoms);
                    assert_eq!(
                        recovered.commitment().unwrap(),
                        body.outputs().outputs()[index as usize].commitment()
                    );
                    assert_eq!(
                        &recovered.encode_plaintext()[..],
                        &plaintext(atoms, blinding)[..]
                    );
                }
                assert_eq!(body, unchanged);
                assert_eq!(
                    &original.encode_plaintext()[..],
                    &plaintext(atoms, 0xa5)[..]
                );
            }
        }
    }

    /// Checks count limits before complete index selection and selection before any payload work.
    #[test]
    fn recovery_preserves_count_and_full_index_error_precedence() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let core = core(vec![
            (NoteCommitment::from_bytes([0; 64]), CryptoSuite::V1);
            3
        ]);
        let output = NoteOutput::new(
            core.outputs()[0].0,
            EncryptedNoteEnvelope::new(
                EncodedMlKem1024Ciphertext::from_bytes([0; 1568]),
                vec![],
                0,
            )
            .unwrap(),
        );
        let body = body(&core, vec![output; 3]);
        let error = recover_payment_output(
            &body,
            u64::MAX,
            &recipient,
            &key,
            PaymentCountLimits::new(1, 1).unwrap(),
            0,
        )
        .unwrap_err();
        assert!(matches!(
            &error,
            NoteRecoveryError::Projection(NoteContextError::PaymentCore(
                PaymentEncryptionCoreError::CountLimitExceeded(
                    PaymentCountLimitsError::InputCountExceedsLimit {
                        actual: 2,
                        maximum: 1
                    }
                )
            ))
        ));
        assert!(error.source().unwrap().is::<NoteContextError>());
        assert!(matches!(
            recover_payment_output(
                &body,
                u64::MAX,
                &recipient,
                &key,
                PaymentCountLimits::new(2, 1).unwrap(),
                0
            ),
            Err(NoteRecoveryError::Projection(
                NoteContextError::PaymentCore(PaymentEncryptionCoreError::CountLimitExceeded(
                    PaymentCountLimitsError::OutputCountExceedsLimit {
                        actual: 3,
                        maximum: 1
                    }
                ))
            ))
        ));
        for index in [3, 256, 65_536, 1_u64 << 32, u64::MAX] {
            let error =
                recover_payment_output(&body, index, &recipient, &key, limits(), 0).unwrap_err();
            assert!(matches!(
                &error,
                NoteRecoveryError::Context(NoteEncryptionContextError::OutputIndexOutOfBounds {
                    index: supplied, output_count: 3,
                }) if *supplied == index
            ));
            assert!(error.source().unwrap().is::<NoteEncryptionContextError>());
        }
    }

    /// Checks every public payload before recovery, including an unselected malformed output.
    #[test]
    fn recovery_rechecks_all_payload_bounds_and_full_suite_headers() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let (_, body) = delivered_body(&recipient, 1);
        for maximum in [0, 32, 83] {
            let error =
                recover_payment_output(&body, 2, &recipient, &key, limits(), maximum).unwrap_err();
            assert!(matches!(
                error,
                NoteRecoveryError::Projection(NoteContextError::OutputPayload {
                    output_index: 0,
                    source: NotePayloadError::PayloadLengthExceedsLimit { actual: 84, maximum: bound },
                }) if bound == maximum
            ));
        }
        let original = body.outputs().outputs()[1].envelope();
        let mut payload = original.payload().to_vec();
        payload.push(0);
        let changed = replace_envelope(
            &body,
            1,
            EncryptedNoteEnvelope::new(original.encapsulation().clone(), payload, 85).unwrap(),
        );
        assert!(matches!(
            recover_payment_output(&changed, 0, &recipient, &key, limits(), 84),
            Err(NoteRecoveryError::Projection(
                NoteContextError::OutputPayload {
                    output_index: 1,
                    source: NotePayloadError::PayloadLengthExceedsLimit {
                        actual: 85,
                        maximum: 84
                    },
                }
            ))
        ));
        assert_eq!(
            recover_payment_output(&changed, 0, &recipient, &key, limits(), 85)
                .unwrap()
                .amount()
                .atoms(),
            1
        );
        for suite in [0_u32, 2, 0x0100_0001, u32::MAX] {
            let mut payload = original.payload().to_vec();
            payload[..4].copy_from_slice(&suite.to_le_bytes());
            let changed = replace_envelope(
                &body,
                1,
                EncryptedNoteEnvelope::new(original.encapsulation().clone(), payload, 84).unwrap(),
            );
            assert!(matches!(
                recover_payment_output(&changed, 0, &recipient, &key, limits(), 84),
                Err(NoteRecoveryError::Projection(NoteContextError::OutputPayload {
                    output_index: 1,
                    source: NotePayloadError::UnsupportedSuite(CryptoSuiteError::Unsupported { id }),
                })) if id.value() == suite
            ));
        }
        for length in [0, 3, 4, 31] {
            let changed = replace_envelope(
                &body,
                1,
                EncryptedNoteEnvelope::new(
                    original.encapsulation().clone(),
                    original.payload()[..length].to_vec(),
                    84,
                )
                .unwrap(),
            );
            assert!(matches!(
                recover_payment_output(&changed, 0, &recipient, &key, limits(), 84),
                Err(NoteRecoveryError::Projection(NoteContextError::OutputPayload {
                    output_index: 1, source: NotePayloadError::TruncatedPayload { actual, .. },
                })) if actual == length
            ));
        }
    }

    /// Checks full network and ownership binding while retaining crypto's grouped key failure.
    #[test]
    fn recovery_requires_the_expected_recipient_and_matching_decryption_capability() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let (_, body) = delivered_body(&recipient, 1);
        for index in 0..64 {
            let mut network = [7; 64];
            network[index] ^= 1;
            let mut bytes = recipient.to_bytes();
            bytes[4..68].copy_from_slice(&network);
            let changed =
                NoteRecipient::from_bytes(&bytes, NetworkId::from_bytes(network)).unwrap();
            assert!(matches!(
                recover_payment_output(&body, 0, &changed, &key, limits(), 84),
                Err(NoteRecoveryError::NetworkMismatch)
            ));
            let mut bytes = recipient.to_bytes();
            bytes[72 + index] ^= 1;
            let changed = NoteRecipient::from_bytes(&bytes, context().network_id()).unwrap();
            assert!(matches!(
                recover_payment_output(&body, 0, &changed, &key, limits(), 84),
                Err(NoteRecoveryError::CommitmentMismatch)
            ));
        }
        let other_key = MlKem1024DecapsulationKey::from_seed(&[12; 64]);
        let other = self::recipient(&other_key, [13; 64]);
        for (recipient, key) in [
            (&recipient, &other_key),
            (&other, &key),
            (&other, &other_key),
        ] {
            let error = recover_payment_output(&body, 0, recipient, key, limits(), 84).unwrap_err();
            assert!(matches!(
                &error,
                NoteRecoveryError::Decryption(NoteDecryptionError::AuthenticationFailed)
            ));
            assert!(error.source().unwrap().is::<NoteDecryptionError>());
        }
    }

    /// Checks commitment agreement even when a malicious sender supplies authenticated valid bytes.
    #[test]
    fn authenticated_plaintext_must_match_every_published_commitment_byte() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let opening = opening(&recipient, 1, 0xa5);
        let commitment = opening.commitment().unwrap();
        for index in 0..64 {
            let mut changed = *commitment.as_bytes();
            changed[index] ^= 1;
            let body = authenticated_body(
                &plaintext(1, 0xa5)[..],
                NoteCommitment::from_bytes(changed),
                &recipient,
            );
            assert!(matches!(
                recover_payment_output(&body, 0, &recipient, &key, limits(), 84),
                Err(NoteRecoveryError::CommitmentMismatch)
            ));
        }
    }

    /// Checks exact lengths, complete versions and positive bounded amounts after authentication.
    #[test]
    fn authenticated_malformed_records_share_the_fixed_plaintext_failure() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let opening = opening(&recipient, 1, 0xa5);
        let commitment = opening.commitment().unwrap();
        for length in (0..52).chain([53, 64]) {
            let mut bytes = Zeroizing::new(vec![0; length]);
            let copied = length.min(52);
            bytes[..copied].copy_from_slice(&plaintext(1, 0xa5)[..copied]);
            let body = authenticated_body(&bytes, commitment, &recipient);
            assert!(matches!(
                recover_payment_output(&body, 0, &recipient, &key, limits(), 96),
                Err(NoteRecoveryError::InvalidPlaintext)
            ));
        }
        for version in [0_u32, 2, 256, 0x0100_0001, u32::MAX] {
            let mut bytes = plaintext(1, 0xa5);
            bytes[..4].copy_from_slice(&version.to_le_bytes());
            let body = authenticated_body(&bytes[..], commitment, &recipient);
            assert!(matches!(
                recover_payment_output(&body, 0, &recipient, &key, limits(), 84),
                Err(NoteRecoveryError::InvalidPlaintext)
            ));
        }
        for atoms in [0, Amount::MAX_ATOMS + 1, u128::MAX] {
            let mut bytes = plaintext(1, 0xa5);
            bytes[4..20].copy_from_slice(&atoms.to_le_bytes());
            let body = authenticated_body(&bytes[..], commitment, &recipient);
            assert!(matches!(
                recover_payment_output(&body, 0, &recipient, &key, limits(), 84),
                Err(NoteRecoveryError::InvalidPlaintext)
            ));
        }
    }

    /// Checks authentication before note parsing and rejects every transmitted envelope component.
    #[test]
    fn authentication_failure_never_reaches_plaintext_validation() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let (_, body) = delivered_body(&recipient, 1);
        let original = body.outputs().outputs()[0].envelope();
        for index in [4, 15, 16, 35, 68, 83] {
            let mut payload = original.payload().to_vec();
            payload[index] ^= 1;
            let changed = replace_envelope(
                &body,
                0,
                EncryptedNoteEnvelope::new(original.encapsulation().clone(), payload, 84).unwrap(),
            );
            assert!(matches!(
                recover_payment_output(&changed, 0, &recipient, &key, limits(), 84),
                Err(NoteRecoveryError::Decryption(
                    NoteDecryptionError::AuthenticationFailed
                ))
            ));
        }
        for index in [0, 1567] {
            let mut encapsulation = *original.encapsulation().as_bytes();
            encapsulation[index] ^= 1;
            let changed = replace_envelope(
                &body,
                0,
                EncryptedNoteEnvelope::new(
                    EncodedMlKem1024Ciphertext::from_bytes(encapsulation),
                    original.payload().to_vec(),
                    84,
                )
                .unwrap(),
            );
            assert!(matches!(
                recover_payment_output(&changed, 0, &recipient, &key, limits(), 84),
                Err(NoteRecoveryError::Decryption(
                    NoteDecryptionError::AuthenticationFailed
                ))
            ));
        }
        let empty = Zeroizing::new(Vec::<u8>::new());
        let malformed =
            authenticated_body(&empty, body.outputs().outputs()[0].commitment(), &recipient);
        let original = malformed.outputs().outputs()[0].envelope();
        let mut payload = original.payload().to_vec();
        payload[31] ^= 1;
        let changed = replace_envelope(
            &malformed,
            0,
            EncryptedNoteEnvelope::new(original.encapsulation().clone(), payload, 32).unwrap(),
        );
        assert!(matches!(
            recover_payment_output(&changed, 0, &recipient, &key, limits(), 84),
            Err(NoteRecoveryError::Decryption(
                NoteDecryptionError::AuthenticationFailed
            ))
        ));
        assert!(matches!(
            recover_payment_output(&malformed, 0, &recipient, &key, limits(), 84),
            Err(NoteRecoveryError::InvalidPlaintext)
        ));
    }

    /// Checks repeated slot identity and complete body reconstruction instead of a supplied digest.
    #[test]
    fn recovery_binds_duplicate_positions_and_all_completed_body_core_fields() {
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(&key, [13; 64]);
        let (_, body) = delivered_body(&recipient, 1);
        let changed = replace_envelope(&body, 0, body.outputs().outputs()[2].envelope().clone());
        assert!(matches!(
            recover_payment_output(&changed, 0, &recipient, &key, limits(), 84),
            Err(NoteRecoveryError::Decryption(
                NoteDecryptionError::AuthenticationFailed
            ))
        ));
        for change in 0..13 {
            let (original, inputs, outputs, mut fee) = body.clone().into_parts();
            let mut outputs = outputs.into_outputs();
            let (mut anchor, mut nullifiers) = inputs.into_parts();
            let mut network = original.network_id();
            let mut protocol = original.protocol_version();
            let mut proof = original.proof_profile_id();
            let mut schedule = original.fee_schedule_id();
            let mut start = CheckpointSequence::new(5);
            let mut end = CheckpointSequence::new(8);
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
                10 => {
                    outputs[1] = NoteOutput::new(
                        NoteCommitment::from_bytes([0; 64]),
                        outputs[1].envelope().clone(),
                    )
                }
                11 => outputs.swap(1, 2),
                12 => {
                    outputs.pop();
                }
                _ => unreachable!(),
            }
            let changed = PaymentBody::new(
                TransactionContext::new(
                    network,
                    protocol,
                    proof,
                    schedule,
                    ValidityCheckpointRange::new(start, end).unwrap(),
                ),
                PaymentInputs::new(anchor, nullifiers, limits()).unwrap(),
                PaymentOutputs::new(outputs, limits()).unwrap(),
                fee,
                limits(),
            )
            .unwrap();
            let error =
                recover_payment_output(&changed, 0, &recipient, &key, limits(), 84).unwrap_err();
            if change == 0 {
                assert!(matches!(error, NoteRecoveryError::NetworkMismatch));
            } else {
                assert!(
                    matches!(
                        error,
                        NoteRecoveryError::Decryption(NoteDecryptionError::AuthenticationFailed)
                    ),
                    "core mutation {change} did not fail authentication"
                );
            }
        }
    }
}
