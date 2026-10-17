//! Encoded commitments to recipient ownership information.

mod error;

pub use error::OwnershipCommitmentError;

/// The 64 byte digest representation of a recipient ownership commitment.
///
/// The proposed recipient descriptor carries this value alongside its address context and full
/// encapsulation public key.
///
/// This container follows the existing Poseidon2 and 512 effective digest bit direction without
/// selecting the exact ownership construction.
///
/// The committed fields, secret opening relation and encryption key context binding remain to be
/// specified.
///
/// Construction preserves every byte pattern without deriving the commitment or establishing
/// that anyone can open it.
///
/// The complete profile must define the field, permutation parameters, capacity, domain framing
/// and canonical output conversion.
///
/// Storing 64 bytes alone does not establish effective digest width or a security level.
///
/// Note and proof consumers must bind the ownership information to the note's prescribed
/// spending and nullifier capabilities.
///
/// This public value is not a secret nullifier key, evidence of spending authority or proof of
/// successful note recovery.
///
/// Its relationship to the advertised encryption key cannot be inferred from storing the two
/// values together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnershipCommitment(
    /// Complete declared ownership digest without an opening claim.
    [u8; 64],
);

impl OwnershipCommitment {
    /// The byte length of the encoded ownership commitment.
    pub const BYTE_LENGTH: usize = 64;

    /// Stores a complete commitment without verifying its derivation or opening.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the complete commitment bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Consumes the value and returns its complete commitment bytes.
    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for OwnershipCommitment {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = OwnershipCommitmentError;

    /// Copies a complete commitment from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipCommitmentError::InvalidByteLength`] if the slice does not contain
    /// exactly [`Self::BYTE_LENGTH`] bytes.
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

/// Construction, conversion and rejection properties of [`OwnershipCommitment`].
#[cfg(test)]
mod tests {
    use super::{OwnershipCommitment, OwnershipCommitmentError};

    /// Checks that slice conversion preserves complete unverified digests in order.
    #[test]
    fn slice_conversion_preserves_complete_unverified_digests_in_order() {
        let patterned = std::array::from_fn::<_, 64, _>(|index| index as u8 ^ 0xa5);

        for bytes in [patterned, [0; 64], [u8::MAX; 64]] {
            let commitment = OwnershipCommitment::try_from(bytes.as_slice()).unwrap();

            assert_eq!(commitment.as_bytes(), &bytes);
            assert_eq!(commitment.into_bytes(), bytes);
            assert_eq!(commitment, OwnershipCommitment::from_bytes(bytes));
        }
    }

    /// Checks that slice conversion rejects truncation and trailing bytes.
    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 32, 63, 65, 128] {
            let bytes = vec![0; length];

            assert!(matches!(
                OwnershipCommitment::try_from(bytes.as_slice()),
                Err(OwnershipCommitmentError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }
}
