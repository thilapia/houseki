//! Ordered ordinary note outputs for a payment.

mod error;

pub use error::PaymentOutputsError;

use super::PaymentCountLimits;
use crate::NoteOutput;

/// A nonempty ordered list of ordinary note outputs within a supplied count limit.
///
/// Recipient notes and optional change share this list.
///
/// The public fee is a separate field of the payment body and never contributes to the output
/// count.
///
/// Construction preserves every entry in order, including repeated commitments or identical
/// outputs.
///
/// Each accepted output creates its own note instance at its assigned original insertion
/// position and must be funded separately.
///
/// Callers must supply the applicable protocol limits and enforce decoding bounds before
/// allocating output lists or payloads.
///
/// Construction checks the actual list length only.
///
/// Consumers must also check active payload and total body byte limits, work limits and proof
/// support, and recheck the count if applicable limits change.
///
/// The containing body must bind the complete ordered outputs into authorization and the
/// expected proof statement.
///
/// This type does not verify conservation, validate encrypted recovery or assign insertion
/// positions or a wire encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentOutputs {
    /// Nonempty ordered ordinary note outputs with multiplicity preserved.
    outputs: Vec<NoteOutput>,
}

impl PaymentOutputs {
    /// Constructs payment outputs without changing their order or multiplicity.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentOutputsError::EmptyOutputs`] for an empty list or
    /// [`PaymentOutputsError::OutputCountExceedsLimit`] for an excessive count.
    pub fn new(
        outputs: Vec<NoteOutput>,
        limits: PaymentCountLimits,
    ) -> Result<Self, PaymentOutputsError> {
        if outputs.is_empty() {
            return Err(PaymentOutputsError::EmptyOutputs);
        }

        if outputs.len() > limits.max_output_count() {
            return Err(PaymentOutputsError::OutputCountExceedsLimit {
                actual: outputs.len(),
                maximum: limits.max_output_count(),
            });
        }

        Ok(Self { outputs })
    }

    /// Borrows the ordinary note outputs in their original order.
    pub fn outputs(&self) -> &[NoteOutput] {
        &self.outputs
    }

    /// Returns the output count derived from the actual list length.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Consumes the outputs and returns the complete ordered list.
    pub fn into_outputs(self) -> Vec<NoteOutput> {
        self.outputs
    }
}

/// Construction, conversion and rejection properties of [`PaymentOutputs`].
#[cfg(test)]
mod tests {
    use super::{PaymentCountLimits, PaymentOutputs, PaymentOutputsError};
    use crate::{EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope, NoteCommitment, NoteOutput};

    /// Builds one declared output with opaque envelope bytes for constructor fixtures.
    fn output(commitment_byte: u8, payload: Vec<u8>) -> NoteOutput {
        let payload_len = payload.len();
        let envelope = EncryptedNoteEnvelope::new(
            EncodedMlKem1024Ciphertext::from_bytes([commitment_byte; 1568]),
            payload,
            payload_len,
        )
        .unwrap();

        NoteOutput::new(NoteCommitment::from_bytes([commitment_byte; 64]), envelope)
    }

    /// Checks that construction preserves order and multiplicity at the output limit.
    #[test]
    fn construction_preserves_order_and_multiplicity_at_the_output_limit() {
        let first = output(3, vec![8, 0, 4]);
        let same_commitment = output(3, vec![5, 6]);
        let list = vec![first.clone(), output(1, vec![9]), same_commitment, first];
        let outputs =
            PaymentOutputs::new(list.clone(), PaymentCountLimits::new(1, 4).unwrap()).unwrap();

        assert_eq!(outputs.outputs(), list.as_slice());
        assert_eq!(outputs.output_count(), 4);
        assert_eq!(outputs.into_outputs(), list);
    }

    /// Checks that construction accepts a single note without a fee or change output.
    #[test]
    fn construction_accepts_a_single_note_without_a_fee_or_change_output() {
        for maximum in [1, 2, usize::MAX] {
            let list = vec![output(0, vec![])];
            let outputs =
                PaymentOutputs::new(list, PaymentCountLimits::new(1, maximum).unwrap()).unwrap();

            assert_eq!(outputs.output_count(), 1);
        }
    }

    /// Checks that construction rejects empty outputs.
    #[test]
    fn construction_rejects_empty_outputs() {
        let result = PaymentOutputs::new(vec![], PaymentCountLimits::new(1, 1).unwrap());

        assert!(matches!(result, Err(PaymentOutputsError::EmptyOutputs)));
    }

    /// Checks that construction rejects excess outputs with the actual count.
    #[test]
    fn construction_rejects_excess_outputs_with_the_actual_count() {
        for (actual, maximum) in [(2, 1), (4, 3)] {
            let result = PaymentOutputs::new(
                vec![output(1, vec![0]); actual],
                PaymentCountLimits::new(usize::MAX, maximum).unwrap(),
            );

            assert!(matches!(
                result,
                Err(PaymentOutputsError::OutputCountExceedsLimit {
                    actual: reported_actual, maximum: reported_maximum,
                }) if reported_actual == actual && reported_maximum == maximum
            ));
        }
    }
}
