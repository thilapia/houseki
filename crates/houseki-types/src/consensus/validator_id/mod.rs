//! Stable Poseidon2 identifiers for validators.

mod error;

pub use error::ValidatorIdError;

/// The 64 byte digest representation of a stable Poseidon2 validator identifier.
///
/// Derivation binds immutable registration data under a dedicated validator domain.
///
/// The identifier remains unchanged when the consensus signing key changes.
///
/// The exact committed fields, domain and canonical encoding remain to be specified.
///
/// Construction stores the complete digest without computing it or verifying registration, and
/// every byte pattern is representable.
///
/// The hash profile must define the field, permutation parameters, sponge capacity, domain
/// framing and output conversion to meet the selected 512 effective digest bit requirement.
///
/// Storing 64 bytes alone establishes neither that width nor a valid field encoding.
///
/// Poseidon2 supports proving registration binding inside a circuit without SHA3 computation.
///
/// Consumers must authenticate the validator state and use the signing key authorized for the
/// relevant committee context.
///
/// This value establishes no key ownership, committee membership, voting weight or reward
/// destination, and it does not authorize a key change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidatorId(
    /// Complete declared stable validator digest without registration evidence.
    [u8; 64],
);

impl ValidatorId {
    /// The byte length of the encoded validator identifier.
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

impl TryFrom<&[u8]> for ValidatorId {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = ValidatorIdError;

    /// Copies a complete identifier from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`ValidatorIdError::InvalidByteLength`] if the slice does not contain exactly
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

/// Construction, conversion and rejection properties of [`ValidatorId`].
#[cfg(test)]
mod tests {
    use super::{ValidatorId, ValidatorIdError};

    /// Checks that slice conversion preserves complete unverified digests in order.
    #[test]
    fn slice_conversion_preserves_complete_unverified_digests_in_order() {
        let patterned = std::array::from_fn::<_, 64, _>(|index| index as u8 ^ 0xa5);

        for bytes in [patterned, [0; 64], [u8::MAX; 64]] {
            let id = ValidatorId::try_from(bytes.as_slice()).unwrap();

            assert_eq!(id.as_bytes(), &bytes);
            assert_eq!(id.into_bytes(), bytes);
        }
    }

    /// Checks that slice conversion rejects truncation and trailing bytes.
    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 32, 63, 65, 128] {
            let bytes = vec![0; length];

            assert!(matches!(
                ValidatorId::try_from(bytes.as_slice()),
                Err(ValidatorIdError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }
}
