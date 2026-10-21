//! Exact activation, fees and bounded resource policy.

mod error;
mod limits;

pub use error::PolicyError;
pub use limits::ExecutionLimits;

use houseki_types::{
    Amount, FeeScheduleId, PaymentBody, ProofProfileId, ProtocolVersion, TransactionContext,
    TransactionKind,
};

/// Immutable activation and resource policy for the native reference ledger.
///
/// Profile activation selects among claims already recognized by the proof registry.
///
/// It never establishes proof validity or changes the meaning of a wallet profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPolicy {
    /// Protocol version active in the checkpoint.
    pub(crate) protocol: ProtocolVersion,

    /// Payment profile identifiers active under the fixed policy.
    pub(crate) payment_profiles: Vec<ProofProfileId>,

    /// Withdrawal profile identifiers active under the fixed policy.
    pub(crate) withdrawal_profiles: Vec<ProofProfileId>,

    /// Identifier binding the fee schedule's meaning and rates.
    pub(crate) fee_schedule: FeeScheduleId,

    /// Constant fee charged for each successful payment.
    pub(crate) payment_base_fee: Amount,

    /// Fee charged for each actual input.
    pub(crate) per_input_fee: Amount,

    /// Fee charged for each actual ordinary output.
    pub(crate) per_output_fee: Amount,

    /// Exact public withdrawal fee.
    pub(crate) withdrawal_fee: Amount,

    /// Canonical resource and anchor bounds.
    pub(crate) limits: ExecutionLimits,
}

impl ExecutionPolicy {
    /// Constructs the explicitly opted in development preset.
    ///
    /// # Errors
    ///
    /// Reports inconsistent fixed fee identity or anchor bounds if the preset is invalid.
    #[cfg(feature = "experimental-profiles")]
    pub fn development() -> Result<Self, PolicyError> {
        let policy = Self {
            protocol: ProtocolVersion::new(1),
            payment_profiles: vec![houseki_proofs::EXPERIMENTAL_PAYMENT_PROFILE],
            withdrawal_profiles: vec![houseki_proofs::EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE],
            fee_schedule: FeeScheduleId::new(0xffff0001),
            payment_base_fee: Amount::from_atoms(0).expect("zero is bounded"),
            per_input_fee: Amount::from_atoms(1).expect("one is bounded"),
            per_output_fee: Amount::from_atoms(1).expect("one is bounded"),
            withdrawal_fee: Amount::from_atoms(1).expect("one is bounded"),
            limits: ExecutionLimits::reference(),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validates anchor coverage and the reserved development fee identity.
    pub(crate) fn validate(&self) -> Result<(), PolicyError> {
        if self.limits.anchor_window == 0
            || self.limits.anchor_retention < self.limits.anchor_window
        {
            return Err(PolicyError::AnchorRetention);
        }
        let maximum = ExecutionLimits::reference();
        if self.limits.body_bytes > maximum.body_bytes
            || self.limits.proof_bytes > maximum.proof_bytes
            || self.limits.output_payload_bytes > maximum.output_payload_bytes
            || self.limits.batch_occurrences > maximum.batch_occurrences
            || self.limits.batch_bytes > maximum.batch_bytes
            || self.limits.fixture_units > maximum.fixture_units
            || self.limits.unit_occurrences > maximum.unit_occurrences
            || self.limits.unit_bytes > maximum.unit_bytes
            || self.limits.note_leaves > maximum.note_leaves
            || self.limits.spent_markers > maximum.spent_markers
            || self.limits.accounts > maximum.accounts
            || self.limits.validators > maximum.validators
            || self.limits.key_descriptor_bytes > maximum.key_descriptor_bytes
            || self.limits.anchor_window > maximum.anchor_window
            || self.limits.anchor_retention > maximum.anchor_retention
        {
            return Err(PolicyError::ResourceBounds);
        }
        if self.fee_schedule.value() == 0xffff0001
            && (
                self.payment_base_fee.atoms(),
                self.per_input_fee.atoms(),
                self.per_output_fee.atoms(),
                self.withdrawal_fee.atoms(),
            ) != (0, 1, 1, 1)
        {
            return Err(PolicyError::FeeScheduleIdentity);
        }
        Ok(())
    }

    /// Computes the exact fee from actual body counts after checking relation support.
    ///
    /// This operation does not check the body's declared fee, context or proof.
    ///
    /// # Errors
    ///
    /// Rejects shapes outside one through four inputs and one through two outputs before
    /// reporting arithmetic overflow or a fee above the amount bound.
    pub fn payment_fee(&self, body: &PaymentBody) -> Result<Amount, PolicyError> {
        let shape = body.shape();
        if !(1..=4).contains(&shape.input_count()) || !(1..=2).contains(&shape.output_count()) {
            return Err(PolicyError::UnsupportedShape);
        }
        let inputs = (shape.input_count() as u128)
            .checked_mul(self.per_input_fee.atoms())
            .ok_or(PolicyError::FeeOverflow)?;
        let outputs = (shape.output_count() as u128)
            .checked_mul(self.per_output_fee.atoms())
            .ok_or(PolicyError::FeeOverflow)?;
        let total = self
            .payment_base_fee
            .atoms()
            .checked_add(inputs)
            .and_then(|sum| sum.checked_add(outputs))
            .ok_or(PolicyError::FeeOverflow)?;
        Amount::from_atoms(total).map_err(|_| PolicyError::FeeOverflow)
    }

    /// Tests activation of an already understood context without performing recognition.
    ///
    /// Network, validity, schedule and exact fee checks belong to separate ordered decisions.
    pub fn activates(&self, kind: TransactionKind, context: TransactionContext) -> bool {
        let profiles = match kind {
            TransactionKind::Payment => &self.payment_profiles,
            TransactionKind::RewardWithdrawal => &self.withdrawal_profiles,
        };
        context.protocol_version() == self.protocol
            && profiles.contains(&context.proof_profile_id())
    }

    /// Returns the active protocol version.
    pub const fn protocol(&self) -> ProtocolVersion {
        self.protocol
    }

    /// Returns the active fee schedule identifier.
    pub const fn fee_schedule(&self) -> FeeScheduleId {
        self.fee_schedule
    }

    /// Returns the constant payment base fee.
    pub const fn payment_base_fee(&self) -> Amount {
        self.payment_base_fee
    }

    /// Returns the fee per input.
    pub const fn per_input_fee(&self) -> Amount {
        self.per_input_fee
    }

    /// Returns the fee per ordinary output.
    pub const fn per_output_fee(&self) -> Amount {
        self.per_output_fee
    }

    /// Returns the exact withdrawal fee.
    pub const fn withdrawal_fee(&self) -> Amount {
        self.withdrawal_fee
    }

    /// Borrows active payment profile identifiers.
    pub fn payment_profiles(&self) -> &[ProofProfileId] {
        &self.payment_profiles
    }

    /// Borrows active withdrawal profile identifiers.
    pub fn withdrawal_profiles(&self) -> &[ProofProfileId] {
        &self.withdrawal_profiles
    }

    /// Borrows immutable resource and anchor bounds.
    pub const fn limits(&self) -> &ExecutionLimits {
        &self.limits
    }

    /// Returns the V1 body encoding code.
    pub const fn body_codec_version(&self) -> u32 {
        1
    }

    /// Returns the V1 reference snapshot scheme code.
    pub const fn state_scheme(&self) -> u32 {
        1
    }

    /// Returns the V1 execution artifact schema code.
    pub const fn artifact_schema(&self) -> u32 {
        1
    }
}

/// Development policy behavior and arithmetic boundaries.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use houseki_types::{
        Amount, CheckpointSequence, EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope,
        FeeScheduleId, NetworkId, NoteCommitment, NoteOutput, NoteRoot, Nullifier, PaymentBody,
        PaymentCountLimits, PaymentInputs, PaymentOutputs, ProofProfileId, ProtocolVersion,
        TransactionContext, ValidityCheckpointRange,
    };

    /// Creates representation-only bodies under deliberately loose count limits.
    fn body(inputs: usize, outputs: usize) -> PaymentBody {
        let limits = PaymentCountLimits::new(8, 8).unwrap();
        let context = TransactionContext::new(
            NetworkId::from_bytes([1; 64]),
            ProtocolVersion::new(1),
            ProofProfileId::new(0xffff0008),
            FeeScheduleId::new(0xffff0001),
            ValidityCheckpointRange::new(CheckpointSequence::new(0), CheckpointSequence::new(9))
                .unwrap(),
        );
        let nullifiers = (0..inputs)
            .map(|i| Nullifier::from_bytes([i as u8; 64]))
            .collect();
        let output = NoteOutput::new(
            NoteCommitment::from_bytes([2; 64]),
            EncryptedNoteEnvelope::new(
                EncodedMlKem1024Ciphertext::from_bytes([0; 1568]),
                vec![],
                0,
            )
            .unwrap(),
        );
        PaymentBody::new(
            context,
            PaymentInputs::new(NoteRoot::from_bytes([3; 64]), nullifiers, limits).unwrap(),
            PaymentOutputs::new(vec![output; outputs], limits).unwrap(),
            Amount::from_atoms(0).unwrap(),
            limits,
        )
        .unwrap()
    }

    /// Catches incorrect fees, profile activation and development resource bounds.
    #[test]
    fn development_policy_is_exact() {
        let policy = ExecutionPolicy::development().unwrap();
        for ((inputs, outputs), expected) in [
            ((1, 1), 2),
            ((1, 2), 3),
            ((2, 1), 3),
            ((2, 2), 4),
            ((3, 1), 4),
            ((3, 2), 5),
            ((4, 1), 5),
            ((4, 2), 6),
        ] {
            assert_eq!(
                policy.payment_fee(&body(inputs, outputs)).unwrap().atoms(),
                expected
            );
        }
        assert_eq!(policy.withdrawal_fee().atoms(), 1);
        assert_eq!(policy.fee_schedule().value(), 0xffff0001);
        assert_eq!(policy.protocol().value(), 1);
        assert_eq!(
            policy.payment_profiles(),
            &[ProofProfileId::new(0xffff0008)]
        );
        assert_eq!(
            policy.withdrawal_profiles(),
            &[ProofProfileId::new(0xffff0007)]
        );
        let limits = policy.limits();
        assert_eq!(
            (
                limits.body_bytes(),
                limits.proof_bytes(),
                limits.output_payload_bytes()
            ),
            (16384, 2097152, 4096)
        );
        assert_eq!(
            (limits.batch_occurrences(), limits.batch_bytes()),
            (64, 16777216)
        );
        assert_eq!(
            (
                limits.fixture_units(),
                limits.unit_occurrences(),
                limits.unit_bytes()
            ),
            (64, 128, 33554432)
        );
        assert_eq!(
            (
                limits.note_leaves(),
                limits.spent_markers(),
                limits.accounts()
            ),
            (4096, 4096, 64)
        );
        assert_eq!(
            (limits.validators(), limits.key_descriptor_bytes()),
            (64, 16384)
        );
        assert_eq!(
            (limits.anchor_window(), limits.anchor_retention()),
            (32, 64)
        );
        assert_eq!(
            (
                policy.body_codec_version(),
                policy.state_scheme(),
                policy.artifact_schema()
            ),
            (1, 1, 1)
        );
    }

    /// Rejects shapes admitted by loose native constructors before computing a fee.
    #[test]
    fn payment_fee_rechecks_actual_shape() {
        let mut policy = ExecutionPolicy::development().unwrap();
        for (inputs, outputs) in [(5, 1), (1, 3), (5, 3)] {
            assert!(matches!(
                policy.payment_fee(&body(inputs, outputs)),
                Err(PolicyError::UnsupportedShape)
            ));
        }
        policy.per_input_fee = Amount::from_atoms(0).unwrap();
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::FeeScheduleIdentity)
        ));
        policy.fee_schedule = FeeScheduleId::new(0xffff0002);
        policy.validate().unwrap();
        assert_eq!(policy.payment_fee(&body(4, 2)).unwrap().atoms(), 2);
        assert!(policy.payment_fee(&body(5, 1)).is_err());
        policy.per_input_fee = Amount::from_atoms(Amount::MAX_ATOMS).unwrap();
        assert!(matches!(
            policy.payment_fee(&body(4, 2)),
            Err(PolicyError::FeeOverflow)
        ));
    }

    /// Rejects windows that would lose eligible anchor metadata.
    #[test]
    fn anchor_configuration_is_validated() {
        let mut policy = ExecutionPolicy::development().unwrap();
        policy.limits.anchor_window = 0;
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::AnchorRetention)
        ));
        policy.limits.anchor_window = 65;
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::AnchorRetention)
        ));
    }
    /// Trusted configuration cannot enlarge the absolute reference state/input capacity envelope.
    #[test]
    fn policy_cannot_expand_reference_caps() {
        let mut policy = ExecutionPolicy::development().unwrap();
        policy.limits.note_leaves = 4097;
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::ResourceBounds)
        ));
    }
}
