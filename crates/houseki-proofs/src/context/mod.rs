//! Recognition of expected transaction context without activation or ledger policy.

mod error;

pub use error::ContextError;

use crate::{
    StatementError,
    profile::{ExpectedIdentity, RegisteredProfile, payment::SupportedPaymentShape},
};
use houseki_types::{BodyCodecLimits, TransactionContext};

/// Recognized rules paired with the caller's complete expected transaction context.
///
/// Recognition does not authenticate network activation, fee correctness or checkpoint eligibility.
///
/// Only profiles admitted by the compiled registry can be constructed.
///
/// The `experimental-profiles` feature permits the explicitly experimental withdrawal profile
/// for qualification work without asserting production security or network activation.
#[derive(Debug)]
pub struct ProofContext {
    /// Exact public context required by subsequent statement construction.
    expected: TransactionContext,

    /// Exact relation identity resolved independently of any supplied proof bytes.
    profile: RegisteredProfile,
}

impl ProofContext {
    /// Resolves supported rules without trusting a proof header to select them.
    ///
    /// # Errors
    ///
    /// Checks the complete protocol identifier before resolving an admitted profile.
    pub fn new(expected: TransactionContext) -> Result<Self, ContextError> {
        if expected.protocol_version().value() != 1 {
            return Err(ContextError::UnsupportedProtocol);
        }

        #[cfg(feature = "experimental-profiles")]
        if expected.proof_profile_id()
            == crate::profile::reward_withdrawal::EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE
        {
            return Ok(Self {
                expected,
                profile: RegisteredProfile::RewardWithdrawal(
                    crate::profile::reward_withdrawal::identity(),
                ),
            });
        }

        Err(ContextError::UnsupportedProfile)
    }

    /// Returns the complete expected context without asserting ledger eligibility.
    pub const fn expected(&self) -> TransactionContext {
        self.expected
    }

    /// Returns the immutable registry identity without interpreting an untrusted proof header.
    pub(crate) const fn identity(&self) -> &ExpectedIdentity {
        self.profile.withdrawal_identity()
    }

    /// Resolves a complete payment family without admitting partial relation profiles.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "payment admission follows the complete family manifest"
        )
    )]
    pub(crate) fn payment_identity(
        &self,
        _shape: SupportedPaymentShape,
    ) -> Result<ExpectedIdentity, StatementError> {
        match self.profile {
            RegisteredProfile::RewardWithdrawal(_) => Err(StatementError::IdentityMismatch),
        }
    }

    /// Returns the representation bounds applied before allocating a canonical body.
    pub fn body_limits(&self) -> BodyCodecLimits {
        self.profile.body_limits()
    }

    /// Returns the inclusive complete proof byte bound.
    pub const fn max_proof_bytes(&self) -> usize {
        crate::profile::MAX_PROOF_BYTES
    }
}

/// Checks exact expected context equality without interpreting activation policy.
pub(crate) fn require_context(
    expected: TransactionContext,
    actual: TransactionContext,
) -> Result<(), ()> {
    if expected == actual { Ok(()) } else { Err(()) }
}

/// Profile rejection and exact expected context checks.
#[cfg(test)]
mod tests {
    use super::*;
    use houseki_types::{
        CheckpointSequence, FeeScheduleId, NetworkId, ProofProfileId, ProtocolVersion,
        ValidityCheckpointRange,
    };

    /// Builds public context data without implying an active protocol configuration.
    fn declared(protocol: u32, profile: u32) -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([7; 64]),
            ProtocolVersion::new(protocol),
            ProofProfileId::new(profile),
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        )
    }

    /// Rejects unregistered profiles, including identities reserved for synthetic tests.
    #[test]
    fn unknown_profile_is_rejected() {
        for id in [0, 1, 2, 0xffff0003, 0xffff0004, u32::MAX] {
            assert!(matches!(
                ProofContext::new(declared(1, id)),
                Err(ContextError::UnsupportedProfile)
            ));
        }
    }

    /// Candidate admission requires an explicit build opt-in and never admits neighboring IDs.
    #[test]
    fn reward_withdrawal_candidate_requires_explicit_opt_in() {
        let identity = crate::profile::reward_withdrawal::identity();
        let result = ProofContext::new(declared(1, identity.profile.value()));
        assert_eq!(result.is_ok(), cfg!(feature = "experimental-profiles"));
        for profile in [0xffff0006, 0xffff0008] {
            assert!(matches!(
                ProofContext::new(declared(1, profile)),
                Err(ContextError::UnsupportedProfile)
            ));
        }
    }

    /// Withdrawal recognition retains its original bounds and cannot supply a payment identity.
    #[test]
    fn profile_bounds_and_identities_remain_family_specific() {
        let identity = crate::profile::reward_withdrawal::identity();
        let context = ProofContext {
            expected: declared(1, identity.profile.value()),
            profile: RegisteredProfile::RewardWithdrawal(identity),
        };

        assert_eq!(context.identity(), &identity);
        assert_eq!(context.max_proof_bytes(), 2_097_152);
        assert_eq!(context.body_limits().max_body_bytes(), 16384);
        assert_eq!(context.body_limits().max_payload_bytes(), 4096);
        assert!(
            context
                .body_limits()
                .payment_counts()
                .validate_shape(houseki_types::PaymentShape::new(4, 2).unwrap())
                .is_err()
        );
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let shape = SupportedPaymentShape::new(inputs, outputs).unwrap();

                assert!(matches!(
                    context.payment_identity(shape),
                    Err(StatementError::IdentityMismatch)
                ));
            }
        }
    }

    /// Checks the complete protocol identifier before looking up a profile.
    #[test]
    fn unsupported_protocol_precedes_profile_lookup() {
        for protocol in [0, 2, 257, u32::MAX] {
            assert!(matches!(
                ProofContext::new(declared(protocol, 0)),
                Err(ContextError::UnsupportedProtocol)
            ));
        }
    }

    /// Rejects changes to any declared context component, including validity endpoints.
    #[test]
    fn context_mismatch_is_rejected() {
        let expected = declared(1, 0xffff0004);

        let mut encoded = [7_u8; 64];
        encoded[63] ^= 1;

        let cases = [
            TransactionContext::new(
                NetworkId::from_bytes(encoded),
                expected.protocol_version(),
                expected.proof_profile_id(),
                expected.fee_schedule_id(),
                expected.validity_checkpoint_range(),
            ),
            declared(2, 0xffff0004),
            declared(1, 0xffff0005),
            TransactionContext::new(
                expected.network_id(),
                expected.protocol_version(),
                expected.proof_profile_id(),
                FeeScheduleId::new(5),
                expected.validity_checkpoint_range(),
            ),
            TransactionContext::new(
                expected.network_id(),
                expected.protocol_version(),
                expected.proof_profile_id(),
                expected.fee_schedule_id(),
                ValidityCheckpointRange::new(
                    CheckpointSequence::new(6),
                    CheckpointSequence::new(8),
                )
                .unwrap(),
            ),
        ];

        assert!(require_context(expected, expected).is_ok());
        for actual in cases {
            assert!(require_context(expected, actual).is_err());
        }
    }
}
