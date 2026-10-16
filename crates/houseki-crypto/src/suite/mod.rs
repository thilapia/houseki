//! Houseki note encryption suite selection, typed cores and output context.

mod context;
mod core_digest;
mod error;
mod payment_encryption_core;
mod recipient_key_binding;
mod reward_withdrawal_encryption_core;

pub use context::{NoteEncryptionContext, NoteEncryptionContextError};
pub use error::CryptoSuiteError;
pub use payment_encryption_core::{PaymentEncryptionCore, PaymentEncryptionCoreError};
pub use reward_withdrawal_encryption_core::{
    RewardWithdrawalEncryptionCore, RewardWithdrawalEncryptionCoreError,
};

use houseki_types::CryptoSuiteId;

/// A recognized Houseki note encryption profile.
///
/// Resolve an untrusted [`CryptoSuiteId`] with [`Self::try_from`]. Each suite
/// names one KEM, KDF and AEAD composition. Callers cannot select those
/// algorithms independently.
///
/// Recognition does not establish that a suite is allowed by the active
/// protocol or matches an address or payload. Consumers must check those
/// relationships and validate the cryptographic material separately.
///
/// This type provides identifier resolution and recipient key binding. Context
/// preparation and associated data belong to [`NoteEncryptionContext`].
/// Payload encoding and authenticated encryption remain separate work. Its
/// Rust discriminant is not a wire encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoSuite {
    /// The first candidate Houseki note encryption profile, numeric ID 1.
    ///
    /// Uses ML-KEM-1024, HKDF with HMAC-SHA-512 and AES-256-GCM-SIV with
    /// a 32 byte key, 12 byte random nonce and 16 byte authentication tag.
    ///
    /// Core digest framing, recipient key binding and associated data are
    /// implemented. Complete suite composition remains pending review and
    /// implementation. This identifies a Houseki profile, not an HPKE suite
    /// or an address, note or protocol version.
    V1,
}

impl CryptoSuite {
    /// Returns the profile's numeric identifier for addresses and payloads.
    pub const fn id(&self) -> CryptoSuiteId {
        match self {
            Self::V1 => CryptoSuiteId::new(1),
        }
    }
}

impl TryFrom<CryptoSuiteId> for CryptoSuite {
    type Error = CryptoSuiteError;

    /// Resolves a recognized suite without selecting a fallback.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoSuiteError::Unsupported`] for every unrecognized
    /// identifier, including zero. This does not check protocol activation.
    fn try_from(id: CryptoSuiteId) -> Result<Self, Self::Error> {
        match id.value() {
            1 => Ok(Self::V1),
            _ => Err(CryptoSuiteError::Unsupported { id }),
        }
    }
}

#[cfg(test)]
mod tests {
    use houseki_types::CryptoSuiteId;

    use super::{CryptoSuite, CryptoSuiteError};

    #[test]
    fn suite_one_resolves_to_the_fixed_v1_profile() {
        assert_eq!(CryptoSuite::V1.id(), CryptoSuiteId::new(1));
        assert_eq!(
            CryptoSuite::try_from(CryptoSuiteId::new(1)).unwrap(),
            CryptoSuite::V1
        );
    }

    #[test]
    fn unknown_suites_are_rejected_with_the_complete_identifier() {
        // Values ending in 1 also catch narrowing to an 8 or 16 bit identifier.
        for value in [0, 2, 255, 256, 257, 65_535, 65_536, 65_537, u32::MAX] {
            let supplied = CryptoSuiteId::new(value);

            assert!(matches!(
                CryptoSuite::try_from(supplied),
                Err(CryptoSuiteError::Unsupported { id }) if id == supplied
            ));
        }
    }
}
