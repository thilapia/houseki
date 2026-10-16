//! Houseki note encryption suite selection, typed cores and output context.

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "awaiting complete envelope operations")
)]
mod aead;
mod context;
mod core_digest;
mod error;
// Complete envelope operations will connect the internal KDF and AEAD path.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "awaiting complete envelope operations")
)]
mod key_derivation;
mod payload;
mod payment_encryption_core;
mod recipient_key_binding;
mod reward_withdrawal_encryption_core;

pub use context::{NoteEncryptionContext, NoteEncryptionContextError};
pub use error::CryptoSuiteError;
pub use payload::NotePayloadError;
pub use payment_encryption_core::{PaymentEncryptionCore, PaymentEncryptionCoreError};
pub use reward_withdrawal_encryption_core::{
    RewardWithdrawalEncryptionCore, RewardWithdrawalEncryptionCoreError,
};

use houseki_types::CryptoSuiteId;

/// A recognized Houseki note encryption profile.
///
/// [`Self::try_from`] resolves the encoded identifier to a fixed KEM, KDF and AEAD composition,
/// and [`Self::id`] returns that identifier for addresses and payloads.
///
/// Recognizing a profile does not establish protocol activation or agreement with either
/// representation.
///
/// The suite provides recipient binding, while typed cores and [`NoteEncryptionContext`]
/// prepare its transaction inputs.
///
/// Internal KDF and AEAD operations consume those inputs, with complete envelope operations
/// still pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoSuite {
    /// The first candidate Houseki note encryption profile, numeric ID 1.
    ///
    /// This profile combines ML-KEM-1024, HKDF with HMAC-SHA-512 and AES-256-GCM-SIV using a 32
    /// byte key, 12 byte random nonce and 16 byte authentication tag.
    ///
    /// Its identifier selects that Houseki composition rather than an HPKE suite or an address,
    /// note or protocol version.
    ///
    /// Core digests, recipient binding, associated data, KDF and AEAD are implemented, while
    /// complete envelope operations remain pending.
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
    /// Error returned when this conversion fails.
    type Error = CryptoSuiteError;

    /// Resolves a recognized suite without selecting a fallback.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoSuiteError::Unsupported`] for every unrecognized identifier, including
    /// zero.
    /// This does not check protocol activation.
    fn try_from(id: CryptoSuiteId) -> Result<Self, Self::Error> {
        match id.value() {
            1 => Ok(Self::V1),
            _ => Err(CryptoSuiteError::Unsupported { id }),
        }
    }
}

/// Suite identifier recognition and unsupported value rejection.
#[cfg(test)]
mod tests {
    use houseki_types::CryptoSuiteId;

    use super::{CryptoSuite, CryptoSuiteError};

    /// Checks the exact numeric assignment of the fixed V1 suite.
    #[test]
    fn suite_one_resolves_to_the_fixed_v1_profile() {
        assert_eq!(CryptoSuite::V1.id(), CryptoSuiteId::new(1));
        assert_eq!(
            CryptoSuite::try_from(CryptoSuiteId::new(1)).unwrap(),
            CryptoSuite::V1
        );
    }

    /// Checks unsupported identifiers without narrowing or fallback.
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
