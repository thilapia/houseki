//! Poseidon2 checkpoint identifiers.

mod error;

pub use error::CheckpointIdError;

/// The 64 byte digest representation of a Poseidon2 checkpoint identifier.
///
/// This value identifies a checkpoint independently of its numeric
/// [`CheckpointSequence`](crate::CheckpointSequence).
///
/// The dedicated domain, committed checkpoint fields and canonical encoding remain to be
/// specified.
///
/// Construction stores the complete digest without computing it or checking that it matches a
/// checkpoint.
///
/// Every byte pattern is representable.
///
/// The hash profile must define the field, permutation parameters, sponge capacity, domain
/// framing and output conversion to meet the selected 512 effective digest bit requirement.
///
/// Storing 64 bytes alone establishes neither that width nor a valid field encoding.
///
/// Poseidon2 supports proving identifier derivation inside a circuit without SHA3 computation.
///
/// Consumers must still bind the checkpoint statement and previous checkpoint to authenticated
/// state and verify the required proofs and certificates.
///
/// This container establishes no continuity, execution validity, consensus finality or data
/// availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointId(
    /// Complete declared checkpoint digest without execution or finality evidence.
    [u8; 64],
);

impl CheckpointId {
    /// The byte length of the encoded checkpoint identifier.
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

impl TryFrom<&[u8]> for CheckpointId {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = CheckpointIdError;

    /// Copies a complete identifier from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointIdError::InvalidByteLength`] if the slice does not contain exactly
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

/// Construction, conversion and rejection properties of [`CheckpointId`].
#[cfg(test)]
mod tests {
    use super::{CheckpointId, CheckpointIdError};

    /// Checks that slice conversion preserves complete unverified digests in order.
    #[test]
    fn slice_conversion_preserves_complete_unverified_digests_in_order() {
        let patterned = std::array::from_fn::<_, 64, _>(|index| index as u8 ^ 0xa5);

        for bytes in [patterned, [0; 64], [u8::MAX; 64]] {
            let id = CheckpointId::try_from(bytes.as_slice()).unwrap();

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
                CheckpointId::try_from(bytes.as_slice()),
                Err(CheckpointIdError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }
}
