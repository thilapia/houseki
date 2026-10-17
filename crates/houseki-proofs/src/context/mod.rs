//! Recognition of expected transaction context without activation or ledger policy.

use houseki_types::{BodyCodecLimits, PaymentCountLimits, TransactionContext};

/// Failure to recognize a supported protocol and proof profile pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContextError {
    /// The declared protocol identifier has no supported representation rules.
    #[error("unsupported protocol")]
    UnsupportedProtocol,

    /// The profile identifier has no admitted immutable configuration.
    #[error("unsupported proof profile")]
    UnsupportedProfile,

    /// A recognized profile does not belong to the expected protocol.
    #[error("proof profile does not match protocol")]
    ProfileProtocolMismatch,
}

/// Recognized rules paired with the caller's complete expected transaction context.
///
/// Recognition does not authenticate network activation, fee correctness or checkpoint eligibility.
///
/// Only profiles admitted by the compiled registry can be constructed.
#[derive(Debug)]
pub struct ProofContext {
    /// Exact public context required by subsequent statement construction.
    expected: TransactionContext,
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

        Err(ContextError::UnsupportedProfile)
    }

    /// Returns the complete expected context without asserting ledger eligibility.
    pub const fn expected(&self) -> TransactionContext {
        self.expected
    }

    /// Returns the representation bounds applied before allocating a canonical body.
    pub fn body_limits(&self) -> BodyCodecLimits {
        BodyCodecLimits::new(
            PaymentCountLimits::new(2, 2).expect("nonzero fixed counts"),
            4096,
            16384,
        )
    }

    /// Returns the inclusive complete proof byte bound.
    pub const fn max_proof_bytes(&self) -> usize {
        2_097_152
    }
}

/// Checks exact expected context equality without interpreting activation policy.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by family statement construction")
)]
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

    /// Never turns unknown or experimental profile identifiers into supported profiles.
    #[test]
    fn unknown_profile_is_rejected() {
        for id in [0, 1, 2, 0xffff0003, 0xffff0004, u32::MAX] {
            assert!(matches!(
                ProofContext::new(declared(1, id)),
                Err(ContextError::UnsupportedProfile)
            ));
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
