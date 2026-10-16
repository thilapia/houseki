//! Typed payment inputs available before note encryption.

mod error;

pub use error::PaymentEncryptionCoreError;

use houseki_types::{
    Amount, NoteCommitment, PaymentCountLimits, PaymentInputs, PaymentShape, TransactionContext,
    TransactionKind,
};

use super::CryptoSuite;

/// A payment's declared fields available before its outputs are encrypted.
///
/// Each output is a note commitment followed by its recognized cryptographic
/// suite. The list preserves order and multiplicity. It contains no encrypted
/// envelopes, recipient keys, plaintext openings, proofs or supplied core digests.
/// The public fee remains separate from the ordinary note outputs.
///
/// Construction requires at least one output and rechecks both actual counts
/// against the supplied limits. [`PaymentInputs`] already requires nonempty,
/// distinct input nullifiers. Borrowing exposes no mutable fields or lists.
///
/// Callers must supply the active limits and bound allocations before building
/// the lists. This does not establish protocol or suite activation, anchor
/// eligibility, conservation, note validity or authority to spend. A change
/// in applicable limits requires rechecking the derived [`Self::shape`].
///
/// This type supplies typed inputs for later internal digest derivation. It
/// does not yet define an encoding, compute a digest or construct an encryption
/// context. Final body assembly must preserve these fields and output order,
/// and match each encrypted payload's suite to its corresponding entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentEncryptionCore {
    context: TransactionContext,
    inputs: PaymentInputs,
    outputs: Vec<(NoteCommitment, CryptoSuite)>,
    public_fee: Amount,
}

impl PaymentEncryptionCore {
    /// Assembles typed payment inputs without requiring encrypted outputs.
    ///
    /// # Errors
    ///
    /// Rejects an empty output list first with
    /// [`PaymentEncryptionCoreError::EmptyOutputs`]. Then checks input and
    /// output maxima in that order, returning
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

#[cfg(test)]
mod tests {
    use houseki_types::{
        CheckpointSequence, FeeScheduleId, NetworkId, NoteRoot, Nullifier, PaymentCountLimitsError,
        ProofProfileId, ProtocolVersion, ValidityCheckpointRange,
    };

    use super::{
        Amount, CryptoSuite, NoteCommitment, PaymentCountLimits, PaymentEncryptionCore,
        PaymentEncryptionCoreError, PaymentInputs, PaymentShape, TransactionContext,
        TransactionKind,
    };

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

    fn outputs() -> Vec<(NoteCommitment, CryptoSuite)> {
        [2, 1, 2]
            .map(|byte| (NoteCommitment::from_bytes([byte; 64]), CryptoSuite::V1))
            .to_vec()
    }

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
