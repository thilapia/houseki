//! Poseidon2 identifiers for public reward accounts.

mod error;

pub use error::RewardAccountIdError;

/// The 64 byte digest representation of a Poseidon2 reward account identifier.
///
/// Derivation binds the network, signature scheme and immutable withdrawal public key under a
/// dedicated reward account domain.
///
/// This value stores the resulting bytes without computing the identifier or verifying that
/// binding.
///
/// Every byte pattern is representable, including unverified digests.
///
/// The hash profile must define the field, permutation parameters, sponge capacity, domain
/// framing, canonical input encoding and output conversion.
///
/// This representation follows the existing 512 effective digest bit direction, which storing 64
/// bytes alone does not establish.
///
/// Consumers must authenticate the account state and verify authority binding under the selected
/// profile.
///
/// Poseidon2 allows that binding to be proved without SHA3 computation, but this container
/// performs no proof verification.
///
/// Withdrawal signature verification remains a separate check outside proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RewardAccountId(
    /// Complete declared reward account digest without derivation evidence.
    [u8; 64],
);

impl RewardAccountId {
    /// The byte length of the encoded reward account identifier.
    pub const BYTE_LENGTH: usize = 64;

    /// Stores a complete identifier without verifying its derivation.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the complete identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Consumes the value and returns its complete identifier bytes.
    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for RewardAccountId {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = RewardAccountIdError;

    /// Copies a complete identifier from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`RewardAccountIdError::InvalidByteLength`] if the slice does not contain exactly
    /// [`Self::BYTE_LENGTH`] bytes.
    ///
    /// Trailing bytes are rejected rather than ignored.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes
            .try_into()
            .map_err(|_| Self::Error::InvalidByteLength {
                actual: bytes.len(),
            })?;

        Ok(Self::from_bytes(bytes))
    }
}

/// Construction, conversion and rejection properties of [`RewardAccountId`].
#[cfg(test)]
mod tests {
    use super::{RewardAccountId, RewardAccountIdError};

    /// Checks that slice conversion preserves complete unverified digests in order.
    #[test]
    fn slice_conversion_preserves_complete_unverified_digests_in_order() {
        let patterned = std::array::from_fn::<_, 64, _>(|index| index as u8 ^ 0xa5);

        for bytes in [patterned, [0; 64], [u8::MAX; 64]] {
            let account_id = RewardAccountId::try_from(bytes.as_slice()).unwrap();

            assert_eq!(account_id.as_bytes(), &bytes);
            assert_eq!(account_id.into_bytes(), bytes);
            assert_eq!(account_id, RewardAccountId::from_bytes(bytes));
        }
    }

    /// Checks that slice conversion rejects truncation and trailing bytes.
    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 32, 63, 65, 128] {
            let bytes = vec![0; length];

            assert!(matches!(
                RewardAccountId::try_from(bytes.as_slice()),
                Err(RewardAccountIdError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }
}
