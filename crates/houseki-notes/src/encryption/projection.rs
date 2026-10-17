//! Checked transaction body projection for reconstructing note encryption inputs.

use super::NoteContextError;
use houseki_crypto::{
    CryptoSuite, PaymentEncryptionCore, PaymentEncryptionCoreError, RewardWithdrawalEncryptionCore,
};
use houseki_types::{PaymentBody, PaymentCountLimits, RewardWithdrawalBody};

/// Projects a completed payment into its typed encryption core.
///
/// Rechecks actual counts before allocating the ordered commitment and suite pairs, resolving
/// every borrowed payload through [`houseki_crypto::CryptoSuite::from_note_payload`].
///
/// The result retains the complete context, anchor, ordered nullifiers and public fee while
/// preserving output order and multiplicity.
///
/// The core owns copies of the input list and output pairs without copying encrypted envelopes.
///
/// Callers supply applicable inclusive count and payload limits and must bound body decoding
/// before allocation, enforce total byte and work limits and check protocol activation.
///
/// Successful projection does not authenticate envelopes, validate notes or establish spending
/// authority, anchor eligibility or transaction validity.
///
/// Before authorization, compare this result with the sender's original core by typed fields
/// as well as its derived digest and separately bind the completed encrypted body.
///
/// # Errors
///
/// Checks input counts before output counts, returning [`NoteContextError::PaymentCore`] on
/// failure before inspecting any payload.
///
/// Payloads are then checked in body order, returning [`NoteContextError::OutputPayload`] with
/// the first failing index and the original payload error without a partial core.
pub fn payment_encryption_core(
    body: &PaymentBody,
    limits: PaymentCountLimits,
    max_payload_bytes: usize,
) -> Result<PaymentEncryptionCore, NoteContextError> {
    limits
        .validate_shape(body.shape())
        .map_err(PaymentEncryptionCoreError::from)?;

    let mut outputs = Vec::with_capacity(body.outputs().output_count());
    for (output_index, output) in body.outputs().outputs().iter().enumerate() {
        let suite = CryptoSuite::from_note_payload(output.envelope().payload(), max_payload_bytes)
            .map_err(|source| NoteContextError::OutputPayload {
                output_index,
                source,
            })?;

        outputs.push((output.commitment(), suite));
    }

    PaymentEncryptionCore::new(
        body.context(),
        body.inputs().clone(),
        outputs,
        body.public_fee(),
        limits,
    )
    .map_err(NoteContextError::from)
}

/// Projects a completed reward withdrawal into its typed encryption core.
///
/// Resolves the sole borrowed payload through [`CryptoSuite::from_note_payload`] before copying
/// the declared authority key and projecting the remaining public fields.
///
/// The result retains the complete context, source account, full encoded authority key, nonce,
/// positive public amount, separate fee and output commitment with its recognized suite.
///
/// The encrypted envelope is excluded from the core and its bytes are not copied.
///
/// Callers supply the applicable inclusive payload limit and must bound body decoding before
/// allocation, enforce total byte and work limits and check protocol activation.
///
/// Projection does not authenticate the envelope, validate the authority key or account binding,
/// check nonce availability or gross debit, or prove that the note contains the public amount.
///
/// Before authorization, compare this result with the sender's original core by typed fields
/// as well as its derived digest and separately bind the completed encrypted body.
///
/// # Errors
///
/// Returns [`NoteContextError::OutputPayload`] with index zero and the original error if the
/// payload exceeds its limit, names an unsupported suite or lacks the recognized layout.
///
/// Core construction failures are preserved as [`NoteContextError::WithdrawalCore`].
pub fn withdrawal_encryption_core(
    body: &RewardWithdrawalBody,
    max_payload_bytes: usize,
) -> Result<RewardWithdrawalEncryptionCore, NoteContextError> {
    let output = body.output();
    let suite = CryptoSuite::from_note_payload(output.envelope().payload(), max_payload_bytes)
        .map_err(|source| NoteContextError::OutputPayload {
            output_index: 0,
            source,
        })?;

    RewardWithdrawalEncryptionCore::new(
        body.context(),
        body.reward_account_id(),
        body.withdrawal_public_key().clone(),
        body.nonce(),
        body.public_amount(),
        body.public_fee(),
        (output.commitment(), suite),
    )
    .map_err(NoteContextError::from)
}

/// Exact core projection, active bounds and observable payload failure order.
#[cfg(test)]
mod tests {
    use crate::{NoteContextError, payment_encryption_core, withdrawal_encryption_core};
    use houseki_crypto::{
        CryptoSuite, CryptoSuiteError, NotePayloadError, PaymentEncryptionCore,
        PaymentEncryptionCoreError, RewardWithdrawalEncryptionCore,
    };
    use houseki_types::{
        Amount, CheckpointSequence, CryptoSuiteId, EncodedMlDsa87PublicKey,
        EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope, FeeScheduleId, NetworkId,
        NoteCommitment, NoteOutput, NoteRoot, Nullifier, PaymentBody, PaymentCountLimits,
        PaymentCountLimitsError, PaymentInputs, PaymentOutputs, PaymentShape, ProofProfileId,
        ProtocolVersion, RewardAccountId, RewardWithdrawalBody, TransactionContext,
        ValidityCheckpointRange, WithdrawalNonce,
    };

    /// Builds a complete declared context with distinct identifiers and checkpoint bounds.
    fn context() -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([7; 64]),
            ProtocolVersion::new(0x0100_0002),
            ProofProfileId::new(0x0200_0003),
            FeeScheduleId::new(0x0300_0004),
            ValidityCheckpointRange::new(
                CheckpointSequence::new(5),
                CheckpointSequence::new(u64::MAX),
            )
            .unwrap(),
        )
    }

    /// Supplies counts large enough to assemble all projection fixtures before revalidation.
    fn limits() -> PaymentCountLimits {
        PaymentCountLimits::new(2, 4).unwrap()
    }

    /// Builds ordered input nullifiers that would change if sorted during projection.
    fn inputs() -> PaymentInputs {
        PaymentInputs::new(
            NoteRoot::from_bytes([8; 64]),
            vec![
                Nullifier::from_bytes([9; 64]),
                Nullifier::from_bytes([2; 64]),
            ],
            limits(),
        )
        .unwrap()
    }

    /// Builds an unauthenticated V1 payload with the requested complete layout length.
    fn payload(length: usize) -> Vec<u8> {
        let mut bytes = vec![0xa5; length];
        bytes[..4].copy_from_slice(&1_u32.to_le_bytes());

        bytes
    }

    /// Pairs a commitment with an opaque envelope accepted under its original byte limit.
    fn output(commitment_byte: u8, payload: Vec<u8>) -> NoteOutput {
        let maximum = payload.len();
        let envelope = EncryptedNoteEnvelope::new(
            EncodedMlKem1024Ciphertext::from_bytes([0; 1568]),
            payload,
            maximum,
        )
        .unwrap();

        NoteOutput::new(NoteCommitment::from_bytes([commitment_byte; 64]), envelope)
    }

    /// Assembles a body with two inputs and a separate public fee under the original limits.
    fn body(outputs: Vec<NoteOutput>) -> PaymentBody {
        PaymentBody::new(
            context(),
            inputs(),
            PaymentOutputs::new(outputs, limits()).unwrap(),
            Amount::from_atoms(17).unwrap(),
            limits(),
        )
        .unwrap()
    }

    /// Assembles a declared withdrawal with a patterned full authority key and distinct amounts.
    fn withdrawal_body(output: NoteOutput) -> RewardWithdrawalBody {
        RewardWithdrawalBody::new(
            context(),
            RewardAccountId::from_bytes([10; 64]),
            EncodedMlDsa87PublicKey::from_bytes(std::array::from_fn(|index| (index % 251) as u8)),
            WithdrawalNonce::new(u64::MAX),
            Amount::from_atoms(19).unwrap(),
            Amount::from_atoms(23).unwrap(),
            output,
        )
        .unwrap()
    }

    /// Checks exact sender core equality without sorting, deduplicating or modifying the body.
    #[test]
    fn projection_matches_sender_core_with_output_order_and_multiplicity() {
        let sender = PaymentEncryptionCore::new(
            context(),
            inputs(),
            vec![
                (NoteCommitment::from_bytes([3; 64]), CryptoSuite::V1),
                (NoteCommitment::from_bytes([1; 64]), CryptoSuite::V1),
                (NoteCommitment::from_bytes([3; 64]), CryptoSuite::V1),
                (NoteCommitment::from_bytes([3; 64]), CryptoSuite::V1),
            ],
            Amount::from_atoms(17).unwrap(),
            limits(),
        )
        .unwrap();

        let first = output(3, payload(32));
        let body = body(vec![
            first.clone(),
            output(1, payload(33)),
            output(3, payload(48)),
            first,
        ]);
        let original = body.clone();

        let projected = payment_encryption_core(&body, limits(), 48).unwrap();

        assert_eq!(projected, sender);
        assert_eq!(projected.digest().unwrap(), sender.digest().unwrap());
        assert_eq!(projected.shape(), PaymentShape::new(2, 4).unwrap());
        assert_eq!(body, original);
    }

    /// Checks tighter input limits before both excessive output counts and malformed payloads.
    #[test]
    fn input_count_limits_precede_output_counts_and_payloads() {
        let body = body(vec![output(3, vec![]), output(1, payload(32))]);

        for maximum_outputs in [1, 4] {
            let result = payment_encryption_core(
                &body,
                PaymentCountLimits::new(1, maximum_outputs).unwrap(),
                0,
            );

            assert!(matches!(
                result,
                Err(NoteContextError::PaymentCore(
                    PaymentEncryptionCoreError::CountLimitExceeded(
                        PaymentCountLimitsError::InputCountExceedsLimit {
                            actual: 2,
                            maximum: 1,
                        }
                    )
                ))
            ));
        }
    }

    /// Checks tighter output limits before any malformed payload is interpreted.
    #[test]
    fn output_count_limits_precede_payloads() {
        let body = body(vec![output(3, vec![]), output(1, payload(32))]);

        let result = payment_encryption_core(&body, PaymentCountLimits::new(2, 1).unwrap(), 0);

        assert!(matches!(
            result,
            Err(NoteContextError::PaymentCore(
                PaymentEncryptionCoreError::CountLimitExceeded(
                    PaymentCountLimitsError::OutputCountExceedsLimit {
                        actual: 2,
                        maximum: 1,
                    }
                )
            ))
        ));
    }

    /// Checks every payload position and retains the first failure before later length errors.
    #[test]
    fn payload_failures_follow_body_order() {
        for failing_index in 0..3 {
            let mut outputs = vec![output(3, payload(32)); failing_index];
            outputs.push(output(1, vec![]));
            outputs.push(output(2, payload(48)));

            let body = body(outputs);

            let result = payment_encryption_core(&body, limits(), 32);

            assert!(matches!(
                result,
                Err(NoteContextError::OutputPayload {
                    output_index,
                    source: NotePayloadError::TruncatedPayload {
                        actual: 0,
                        minimum: 4,
                    },
                }) if output_index == failing_index
            ));
        }
    }

    /// Checks a tightened payload limit before interpreting that output's unsupported header.
    #[test]
    fn payload_limits_are_rechecked_before_suite_resolution() {
        let mut bytes = payload(48);
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());

        let body = body(vec![output(3, payload(32)), output(1, bytes)]);

        let result = payment_encryption_core(&body, limits(), 47);

        assert!(matches!(
            result,
            Err(NoteContextError::OutputPayload {
                output_index: 1,
                source: NotePayloadError::PayloadLengthExceedsLimit {
                    actual: 48,
                    maximum: 47,
                },
            })
        ));
    }

    /// Checks complete suite identifiers without truncation, fallback or a partial core.
    #[test]
    fn unsupported_payload_suites_preserve_all_identifier_bits() {
        for id in [0, 2, 257, 65_537, 0x0100_0001, u32::MAX] {
            let mut bytes = payload(32);
            bytes[..4].copy_from_slice(&id.to_le_bytes());

            let body = body(vec![output(3, payload(32)), output(1, bytes)]);

            let result = payment_encryption_core(&body, limits(), 32);

            assert!(matches!(
                result,
                Err(NoteContextError::OutputPayload {
                    output_index: 1,
                    source: NotePayloadError::UnsupportedSuite(CryptoSuiteError::Unsupported {
                        id: reported,
                    }),
                }) if reported == CryptoSuiteId::new(id)
            ));
        }
    }

    /// Checks incomplete headers, nonces and tags after a valid preceding output.
    #[test]
    fn truncated_payloads_retain_the_required_minimum_length() {
        for actual in 0..32 {
            let mut bytes = vec![0; actual];
            if let Some(first) = bytes.first_mut() {
                *first = 1;
            }

            let body = body(vec![output(3, payload(32)), output(1, bytes)]);
            let expected_minimum = if actual < 4 { 4 } else { 32 };

            let result = payment_encryption_core(&body, limits(), 32);

            assert!(matches!(
                result,
                Err(NoteContextError::OutputPayload {
                    output_index: 1,
                    source: NotePayloadError::TruncatedPayload {
                        actual: reported,
                        minimum,
                    },
                }) if reported == actual && minimum == expected_minimum
            ));
        }
    }

    /// Checks inclusive payload and count limits without treating the fee as a note output.
    #[test]
    fn minimum_payment_accepts_exact_limits_with_a_separate_fee() {
        let limits = PaymentCountLimits::new(1, 1).unwrap();

        for atoms in [0, Amount::MAX_ATOMS] {
            let body = PaymentBody::new(
                context(),
                PaymentInputs::new(
                    NoteRoot::from_bytes([8; 64]),
                    vec![Nullifier::from_bytes([9; 64])],
                    limits,
                )
                .unwrap(),
                PaymentOutputs::new(vec![output(3, payload(32))], limits).unwrap(),
                Amount::from_atoms(atoms).unwrap(),
                limits,
            )
            .unwrap();

            let projected = payment_encryption_core(&body, limits, 32).unwrap();

            assert_eq!(projected.shape(), PaymentShape::new(1, 1).unwrap());
            assert_eq!(projected.public_fee().atoms(), atoms);
        }
    }

    /// Checks that envelope bytes are excluded and layout resolution makes no authenticity claim.
    #[test]
    fn projection_excludes_encapsulation_nonce_ciphertext_and_tag_bytes() {
        let first = body(vec![output(3, payload(48))]);

        let mut bytes = payload(48);
        bytes[4..].fill(0xff);
        let second = body(vec![NoteOutput::new(
            NoteCommitment::from_bytes([3; 64]),
            EncryptedNoteEnvelope::new(
                EncodedMlKem1024Ciphertext::from_bytes([0xff; 1568]),
                bytes,
                48,
            )
            .unwrap(),
        )]);

        let first_core = payment_encryption_core(&first, limits(), 48).unwrap();
        let second_core = payment_encryption_core(&second, limits(), 48).unwrap();

        assert_ne!(first, second);
        assert_eq!(first_core, second_core);
        assert_eq!(first_core.digest().unwrap(), second_core.digest().unwrap());
    }

    /// Checks exact sender core equality while retaining every declared source and output field.
    #[test]
    fn withdrawal_projection_matches_the_complete_sender_core() {
        let sender = RewardWithdrawalEncryptionCore::new(
            context(),
            RewardAccountId::from_bytes([10; 64]),
            EncodedMlDsa87PublicKey::from_bytes(std::array::from_fn(|index| (index % 251) as u8)),
            WithdrawalNonce::new(u64::MAX),
            Amount::from_atoms(19).unwrap(),
            Amount::from_atoms(23).unwrap(),
            (NoteCommitment::from_bytes([3; 64]), CryptoSuite::V1),
        )
        .unwrap();

        let body = withdrawal_body(output(3, payload(48)));
        let original = body.clone();

        let projected = withdrawal_encryption_core(&body, 48).unwrap();

        assert_eq!(projected, sender);
        assert_eq!(projected.digest().unwrap(), sender.digest().unwrap());
        assert_eq!(body, original);
    }

    /// Checks the active payload bound before interpreting a malformed or unsupported layout.
    #[test]
    fn withdrawal_payload_limits_precede_header_and_layout_checks() {
        let mut unknown = payload(48);
        unknown[..4].copy_from_slice(&u32::MAX.to_le_bytes());

        for bytes in [vec![0], payload(31), unknown] {
            let actual = bytes.len();
            let maximum = actual - 1;
            let body = withdrawal_body(output(3, bytes));

            let result = withdrawal_encryption_core(&body, maximum);

            assert!(matches!(
                result,
                Err(NoteContextError::OutputPayload {
                    output_index: 0,
                    source: NotePayloadError::PayloadLengthExceedsLimit {
                        actual: reported,
                        maximum: limit,
                    },
                }) if reported == actual && limit == maximum
            ));
        }
    }

    /// Checks full unsupported identifiers before assuming any recognized nonce or tag layout.
    #[test]
    fn withdrawal_unknown_suites_preserve_all_identifier_bits() {
        for id in [0, 2, 257, 65_537, 0x0100_0001, u32::MAX] {
            for length in [4, 32] {
                let mut bytes = payload(length);
                bytes[..4].copy_from_slice(&id.to_le_bytes());

                let body = withdrawal_body(output(3, bytes));

                let result = withdrawal_encryption_core(&body, length);

                assert!(matches!(
                    result,
                    Err(NoteContextError::OutputPayload {
                        output_index: 0,
                        source: NotePayloadError::UnsupportedSuite(CryptoSuiteError::Unsupported {
                            id: reported,
                        }),
                    }) if reported == CryptoSuiteId::new(id)
                ));
            }
        }
    }

    /// Checks incomplete suite headers, nonces and tags with the sole output's zero index.
    #[test]
    fn withdrawal_truncated_payloads_retain_the_required_minimum_length() {
        for actual in 0..32 {
            let mut bytes = vec![0; actual];
            if let Some(first) = bytes.first_mut() {
                *first = 1;
            }

            let body = withdrawal_body(output(3, bytes));
            let expected_minimum = if actual < 4 { 4 } else { 32 };

            let result = withdrawal_encryption_core(&body, actual);

            assert!(matches!(
                result,
                Err(NoteContextError::OutputPayload {
                    output_index: 0,
                    source: NotePayloadError::TruncatedPayload {
                        actual: reported,
                        minimum,
                    },
                }) if reported == actual && minimum == expected_minimum
            ));
        }
    }

    /// Checks exact payload bounds and amount retention while leaving execution checks to callers.
    #[test]
    fn withdrawal_projection_preserves_boundary_amounts_fees_and_exhausted_nonce() {
        for (amount, fee, length) in [
            (1, 0, 32),
            (Amount::MAX_ATOMS, 0, 33),
            (1, Amount::MAX_ATOMS, 48),
            (Amount::MAX_ATOMS, Amount::MAX_ATOMS, 32),
        ] {
            let (context, account, key, nonce, _, _, output) =
                withdrawal_body(output(3, payload(length))).into_parts();
            let body = RewardWithdrawalBody::new(
                context,
                account,
                key,
                nonce,
                Amount::from_atoms(amount).unwrap(),
                Amount::from_atoms(fee).unwrap(),
                output,
            )
            .unwrap();

            let projected = withdrawal_encryption_core(&body, length).unwrap();

            assert_eq!(projected.public_amount().atoms(), amount);
            assert_eq!(projected.public_fee().atoms(), fee);
            assert_eq!(projected.nonce().value(), u64::MAX);
        }
    }

    /// Checks envelope exclusion while keeping the withdrawal's source and effect fields fixed.
    #[test]
    fn withdrawal_projection_excludes_encrypted_envelope_bytes() {
        let first = withdrawal_body(output(3, payload(48)));

        let mut bytes = payload(48);
        bytes[4..].fill(0xff);
        let second = withdrawal_body(NoteOutput::new(
            NoteCommitment::from_bytes([3; 64]),
            EncryptedNoteEnvelope::new(
                EncodedMlKem1024Ciphertext::from_bytes([0xff; 1568]),
                bytes,
                48,
            )
            .unwrap(),
        ));

        let first_core = withdrawal_encryption_core(&first, 48).unwrap();
        let second_core = withdrawal_encryption_core(&second, 48).unwrap();

        assert_ne!(first, second);
        assert_eq!(first_core, second_core);
        assert_eq!(first_core.digest().unwrap(), second_core.digest().unwrap());
    }
}
