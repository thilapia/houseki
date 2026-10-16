//! Checked payment body projection for reconstructing note encryption inputs.

use houseki_crypto::{CryptoSuite, PaymentEncryptionCore, PaymentEncryptionCoreError};
use houseki_types::{PaymentBody, PaymentCountLimits};

use super::NoteContextError;

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

/// Exact core projection, active bounds and observable payload failure order.
#[cfg(test)]
mod tests {
    use houseki_crypto::{
        CryptoSuite, CryptoSuiteError, NotePayloadError, PaymentEncryptionCore,
        PaymentEncryptionCoreError,
    };
    use houseki_types::{
        Amount, CheckpointSequence, CryptoSuiteId, EncodedMlKem1024Ciphertext,
        EncryptedNoteEnvelope, FeeScheduleId, NetworkId, NoteCommitment, NoteOutput, NoteRoot,
        Nullifier, PaymentBody, PaymentCountLimits, PaymentCountLimitsError, PaymentInputs,
        PaymentOutputs, PaymentShape, ProofProfileId, ProtocolVersion, TransactionContext,
        ValidityCheckpointRange,
    };

    use crate::{NoteContextError, payment_encryption_core};

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
}
