//! Typed payment inputs available before note encryption.

mod error;

pub use error::PaymentEncryptionCoreError;

use super::CryptoSuite;
use houseki_types::{
    Amount, NoteCommitment, PaymentCountLimits, PaymentInputs, PaymentShape, TransactionContext,
    TransactionKind,
};

/// A payment's declared fields before output encryption.
///
/// Each output pairs a note commitment with a recognized suite, preserving order and
/// multiplicity while keeping the public fee separate.
///
/// Construction requires at least one output and checks both actual counts against the supplied
/// limits, building on [`PaymentInputs`]' requirement for nonempty, distinct nullifiers.
///
/// The caller must bound allocations before building the lists and supply active limits,
/// rechecking [`Self::shape`] if those limits change.
///
/// These structural checks do not establish anchor eligibility, value conservation, note
/// validity or spending authority.
///
/// [`Self::digest`] binds the declared fields without encrypted envelopes, recipient keys,
/// openings or proofs.
///
/// To preserve that binding, final body assembly must retain the same fields and output order
/// and match each payload suite to its entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentEncryptionCore {
    /// Declared context shared by every payment output.
    context: TransactionContext,

    /// Validated input list and its declared anchor.
    inputs: PaymentInputs,

    /// Ordered commitments and recognized suites, preserving duplicate commitments.
    outputs: Vec<(NoteCommitment, CryptoSuite)>,

    /// Declared fee in atoms, separate from ordinary outputs.
    public_fee: Amount,
}

impl PaymentEncryptionCore {
    /// Assembles typed payment inputs without requiring encrypted outputs.
    ///
    /// # Errors
    ///
    /// Rejects an empty output list first with [`PaymentEncryptionCoreError::EmptyOutputs`].
    ///
    /// Then checks input and output maxima in that order, returning
    /// [`PaymentEncryptionCoreError::CountLimitExceeded`] on failure.
    pub fn new(
        context: TransactionContext,
        inputs: PaymentInputs,
        outputs: Vec<(NoteCommitment, CryptoSuite)>,
        public_fee: Amount,
        limits: PaymentCountLimits,
    ) -> Result<Self, PaymentEncryptionCoreError> {
        if outputs.is_empty() {
            return Err(PaymentEncryptionCoreError::EmptyOutputs);
        }

        let core = Self {
            context,
            inputs,
            outputs,
            public_fee,
        };

        limits.validate_shape(core.shape())?;

        Ok(core)
    }

    /// Returns the payment kind implied by this core.
    pub const fn kind(&self) -> TransactionKind {
        TransactionKind::Payment
    }

    /// Returns the complete declared transaction context.
    pub const fn context(&self) -> TransactionContext {
        self.context
    }

    /// Borrows the declared anchor and ordered input nullifiers.
    pub const fn inputs(&self) -> &PaymentInputs {
        &self.inputs
    }

    /// Borrows ordered pairs of note commitment and recognized suite.
    pub fn outputs(&self) -> &[(NoteCommitment, CryptoSuite)] {
        &self.outputs
    }

    /// Returns the declared public fee separately from ordinary note outputs.
    pub const fn public_fee(&self) -> Amount {
        self.public_fee
    }

    /// Derives the payment shape from the actual lists, excluding the fee.
    pub fn shape(&self) -> PaymentShape {
        PaymentShape::new(self.inputs.input_count(), self.outputs.len())
            .expect("payment encryption core input and output lists are nonempty")
    }

    /// Consumes the core and returns its fields for later body assembly.
    pub fn into_parts(
        self,
    ) -> (
        TransactionContext,
        PaymentInputs,
        Vec<(NoteCommitment, CryptoSuite)>,
        Amount,
    ) {
        (self.context, self.inputs, self.outputs, self.public_fee)
    }
}

/// Payment core retention and count validation order.
#[cfg(test)]
mod tests {
    use super::{
        Amount, CryptoSuite, NoteCommitment, PaymentCountLimits, PaymentEncryptionCore,
        PaymentEncryptionCoreError, PaymentInputs, PaymentShape, TransactionContext,
        TransactionKind,
    };
    use houseki_types::{
        CheckpointSequence, FeeScheduleId, NetworkId, NoteRoot, Nullifier, PaymentCountLimitsError,
        ProofProfileId, ProtocolVersion, ValidityCheckpointRange,
    };

    /// Builds a declared context fixture for this module's binding checks.
    fn context() -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([1; 64]),
            ProtocolVersion::new(2),
            ProofProfileId::new(3),
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        )
    }

    /// Builds the ordered input fixture and its anchor.
    fn inputs() -> PaymentInputs {
        PaymentInputs::new(
            NoteRoot::from_bytes([9; 64]),
            vec![
                Nullifier::from_bytes([3; 64]),
                Nullifier::from_bytes([1; 64]),
            ],
            PaymentCountLimits::new(2, 3).unwrap(),
        )
        .unwrap()
    }

    /// Builds ordered output fixtures including a duplicate commitment.
    fn outputs() -> Vec<(NoteCommitment, CryptoSuite)> {
        [2, 1, 2]
            .map(|byte| (NoteCommitment::from_bytes([byte; 64]), CryptoSuite::V1))
            .to_vec()
    }

    /// Checks retention of all payment fields and duplicate output positions.
    #[test]
    fn construction_preserves_complete_inputs_output_order_and_multiplicity() {
        let context = context();
        let inputs = inputs();
        let outputs = outputs();
        let fee = Amount::from_atoms(17).unwrap();

        let core = PaymentEncryptionCore::new(
            context,
            inputs.clone(),
            outputs.clone(),
            fee,
            PaymentCountLimits::new(2, 3).unwrap(),
        )
        .unwrap();

        assert_eq!(core.kind(), TransactionKind::Payment);
        assert_eq!(core.context(), context);
        assert_eq!(core.inputs(), &inputs);
        assert_eq!(core.outputs(), outputs.as_slice());
        assert_eq!(core.public_fee(), fee);
        assert_eq!(core.shape(), PaymentShape::new(2, 3).unwrap());
        assert_eq!(core.into_parts(), (context, inputs, outputs, fee));
    }

    /// Checks empty output rejection takes precedence over count limits.
    #[test]
    fn empty_outputs_are_rejected_before_count_limits() {
        for maximum_inputs in [1, 2] {
            let result = PaymentEncryptionCore::new(
                context(),
                inputs(),
                vec![],
                Amount::from_atoms(0).unwrap(),
                PaymentCountLimits::new(maximum_inputs, 1).unwrap(),
            );

            assert!(matches!(
                result,
                Err(PaymentEncryptionCoreError::EmptyOutputs)
            ));
        }
    }

    /// Checks that construction revalidates input limits first.
    #[test]
    fn input_limits_are_rechecked_before_output_limits() {
        for maximum_outputs in [1, 3] {
            let result = PaymentEncryptionCore::new(
                context(),
                inputs(),
                outputs(),
                Amount::from_atoms(0).unwrap(),
                PaymentCountLimits::new(1, maximum_outputs).unwrap(),
            );

            assert!(matches!(
                result,
                Err(PaymentEncryptionCoreError::CountLimitExceeded(
                    PaymentCountLimitsError::InputCountExceedsLimit {
                        actual: 2,
                        maximum: 1,
                    }
                ))
            ));
        }
    }

    /// Checks output count rejection after inputs satisfy their limit.
    #[test]
    fn output_limits_are_enforced_after_inputs_fit() {
        let result = PaymentEncryptionCore::new(
            context(),
            inputs(),
            outputs(),
            Amount::from_atoms(0).unwrap(),
            PaymentCountLimits::new(2, 2).unwrap(),
        );

        assert!(matches!(
            result,
            Err(PaymentEncryptionCoreError::CountLimitExceeded(
                PaymentCountLimitsError::OutputCountExceedsLimit {
                    actual: 3,
                    maximum: 2,
                }
            ))
        ));
    }

    /// Checks the minimum output count and separate fee treatment.
    #[test]
    fn one_output_is_sufficient_and_the_fee_never_counts_as_an_output() {
        for atoms in [0, 1, Amount::MAX_ATOMS] {
            let core = PaymentEncryptionCore::new(
                context(),
                inputs(),
                vec![(NoteCommitment::from_bytes([4; 64]), CryptoSuite::V1)],
                Amount::from_atoms(atoms).unwrap(),
                PaymentCountLimits::new(2, 1).unwrap(),
            )
            .unwrap();

            assert_eq!(core.shape(), PaymentShape::new(2, 1).unwrap());
            assert_eq!(core.public_fee().atoms(), atoms);
        }
    }
}
