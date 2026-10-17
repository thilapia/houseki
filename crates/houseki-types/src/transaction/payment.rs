//! Declared payment effects and the context that authorizes them.

use super::{
    PaymentCountLimits, PaymentCountLimitsError, PaymentInputs, PaymentOutputs, PaymentShape,
    TransactionContext, TransactionKind,
};
use crate::Amount;

/// A payment's declared context, note inputs, ordinary note outputs and public fee.
///
/// The input and output wrappers preserve nonempty ordered lists, with distinct input
/// nullifiers.
///
/// Construction derives the shape from those lists and checks both counts against one supplied
/// limit set, even if the wrappers were built under different limits.
///
/// The body exposes no mutable list access and its kind is always [`TransactionKind::Payment`].
///
/// The public fee is mandatory and separate from ordinary note outputs.
///
/// It does not increase the output count, and optional change needs no special field.
///
/// Every [`Amount`] is representable as a declared fee.
///
/// Execution must check the exact fee required by the active schedule and determine its
/// beneficiary from the including validator.
///
/// The body contains no beneficiary choice.
///
/// Callers must supply the applicable count limits, enforce bounds before decoding allocations
/// and check active payload, total byte and work limits separately.
///
/// Construction does not verify context support, proof validity, conservation, anchor
/// eligibility, unspentness or encrypted note recovery.
///
/// Consumers must recheck limits if the applicable protocol context changes.
///
/// Authorization and the expected proof statement must bind the payment kind,
/// context, anchor, actual counts, ordered effects and complete encrypted
/// envelopes.
///
/// The V1 canonical codec preserves these effects under explicit active limits.
///
/// This type carries no proof and establishes no transaction identifier or additional
/// payment class.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentBody {
    /// Declared network, rule identifiers and validity window.
    context: TransactionContext,

    /// Declared anchor and nonempty ordered distinct nullifiers.
    inputs: PaymentInputs,

    /// Nonempty ordered ordinary note outputs, including any change.
    outputs: PaymentOutputs,

    /// Declared public fee, separate from ordinary note outputs.
    public_fee: Amount,
}

impl PaymentBody {
    /// Assembles a payment and checks its actual counts against the supplied limits.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentCountLimitsError::InputCountExceedsLimit`] or
    /// [`PaymentCountLimitsError::OutputCountExceedsLimit`] when a list exceeds its maximum,
    /// checking inputs first.
    ///
    /// This does not define execution check priority or establish that these are the active
    /// protocol limits.
    pub fn new(
        context: TransactionContext,
        inputs: PaymentInputs,
        outputs: PaymentOutputs,
        public_fee: Amount,
        limits: PaymentCountLimits,
    ) -> Result<Self, PaymentCountLimitsError> {
        let body = Self {
            context,
            inputs,
            outputs,
            public_fee,
        };
        limits.validate_shape(body.shape())?;

        Ok(body)
    }

    /// Returns the payment operation kind implied by this body.
    pub const fn kind(&self) -> TransactionKind {
        TransactionKind::Payment
    }

    /// Returns the declared network, rule identifiers and validity window.
    pub const fn context(&self) -> TransactionContext {
        self.context
    }

    /// Borrows the declared anchor and ordered input nullifiers.
    pub const fn inputs(&self) -> &PaymentInputs {
        &self.inputs
    }

    /// Borrows the ordered ordinary note outputs.
    pub const fn outputs(&self) -> &PaymentOutputs {
        &self.outputs
    }

    /// Returns the declared public fee separately from ordinary note outputs.
    pub const fn public_fee(&self) -> Amount {
        self.public_fee
    }

    /// Derives the shape from the actual input and ordinary note output lists.
    pub fn shape(&self) -> PaymentShape {
        PaymentShape::new(self.inputs.input_count(), self.outputs.output_count())
            .expect("payment input and output lists are nonempty")
    }

    /// Consumes the body and returns its context, inputs, outputs and public fee.
    pub fn into_parts(self) -> (TransactionContext, PaymentInputs, PaymentOutputs, Amount) {
        (self.context, self.inputs, self.outputs, self.public_fee)
    }
}

/// Construction, conversion and rejection properties of [`PaymentBody`].
#[cfg(test)]
mod tests {
    use super::{
        Amount, PaymentBody, PaymentCountLimits, PaymentCountLimitsError, PaymentInputs,
        PaymentOutputs, PaymentShape, TransactionContext, TransactionKind,
    };
    use crate::{
        CheckpointSequence, EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope, FeeScheduleId,
        NetworkId, NoteCommitment, NoteOutput, NoteRoot, Nullifier, ProofProfileId,
        ProtocolVersion, ValidityCheckpointRange,
    };

    /// Builds a complete declared context for constructor boundary fixtures.
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

    /// Builds ordered input markers and repeated ordinary outputs at selected counts.
    fn lists(input_count: usize, output_count: usize) -> (PaymentInputs, PaymentOutputs) {
        let limits = PaymentCountLimits::new(input_count, output_count).unwrap();
        let nullifiers = (0..input_count)
            .map(|index| {
                let mut bytes = [0; 64];
                bytes[..size_of::<usize>()].copy_from_slice(&index.to_le_bytes());
                Nullifier::from_bytes(bytes)
            })
            .collect();
        let inputs = PaymentInputs::new(NoteRoot::from_bytes([9; 64]), nullifiers, limits).unwrap();
        let envelope = EncryptedNoteEnvelope::new(
            EncodedMlKem1024Ciphertext::from_bytes([10; 1568]),
            vec![11, 12, 13],
            3,
        )
        .unwrap();
        let output = NoteOutput::new(NoteCommitment::from_bytes([14; 64]), envelope);
        let outputs = PaymentOutputs::new(vec![output; output_count], limits).unwrap();
        (inputs, outputs)
    }

    /// Checks that construction binds shape to lists and preserves all declared fields.
    #[test]
    fn construction_binds_shape_to_lists_and_preserves_all_declared_fields() {
        let (inputs, outputs) = lists(3, 2);
        let context = context();
        let fee = Amount::from_atoms(17).unwrap();
        let body = PaymentBody::new(
            context,
            inputs.clone(),
            outputs.clone(),
            fee,
            PaymentCountLimits::new(3, 2).unwrap(),
        )
        .unwrap();

        assert_eq!(body.shape(), PaymentShape::new(3, 2).unwrap());
        assert_eq!(body.kind(), TransactionKind::Payment);
        assert_eq!(body.context(), context);
        assert_eq!(body.inputs(), &inputs);
        assert_eq!(body.outputs(), &outputs);
        assert_eq!(body.public_fee(), fee);
        assert_eq!(body.into_parts(), (context, inputs, outputs, fee));
    }

    /// Checks that a single output remains valid regardless of the declared fee.
    #[test]
    fn a_single_output_remains_valid_regardless_of_the_declared_fee() {
        for atoms in [0, 1, Amount::MAX_ATOMS] {
            let (inputs, outputs) = lists(1, 1);
            let body = PaymentBody::new(
                context(),
                inputs,
                outputs,
                Amount::from_atoms(atoms).unwrap(),
                PaymentCountLimits::new(2, 3).unwrap(),
            )
            .unwrap();

            assert_eq!(body.shape(), PaymentShape::new(1, 1).unwrap());
            assert_eq!(body.public_fee().atoms(), atoms);
        }
    }

    /// Checks that construction rechecks input limits before output limits.
    #[test]
    fn construction_rechecks_input_limits_before_output_limits() {
        for maximum_outputs in [1, 2] {
            let (inputs, outputs) = lists(3, 2);
            let result = PaymentBody::new(
                context(),
                inputs,
                outputs,
                Amount::from_atoms(0).unwrap(),
                PaymentCountLimits::new(2, maximum_outputs).unwrap(),
            );

            assert!(matches!(
                result,
                Err(PaymentCountLimitsError::InputCountExceedsLimit {
                    actual: 3,
                    maximum: 2
                })
            ));
        }
    }

    /// Checks that construction rechecks output limits after inputs fit.
    #[test]
    fn construction_rechecks_output_limits_after_inputs_fit() {
        let (inputs, outputs) = lists(1, 3);
        let result = PaymentBody::new(
            context(),
            inputs,
            outputs,
            Amount::from_atoms(0).unwrap(),
            PaymentCountLimits::new(1, 2).unwrap(),
        );

        assert!(matches!(
            result,
            Err(PaymentCountLimitsError::OutputCountExceedsLimit {
                actual: 3,
                maximum: 2
            })
        ));
    }
}
