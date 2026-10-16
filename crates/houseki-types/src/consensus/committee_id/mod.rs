//! Poseidon2 identifiers for committee snapshots.

mod error;

pub use error::CommitteeIdError;

/// The 64 byte digest representation of a Poseidon2 committee snapshot identifier.
///
/// Committee context pairs this identifier with an [`Epoch`](crate::Epoch).
/// The snapshot binds validator identities, consensus signing keys, voting
/// weights and reward mappings. Its complete schema, canonical ordering,
/// dedicated domain and encoding remain to be specified. Construction stores
/// the digest without computing it or checking the snapshot, and every byte
/// pattern is representable.
///
/// The hash profile must define the field, permutation parameters, sponge
/// capacity, domain framing and output conversion to meet the selected
/// 512 effective digest bit requirement. Storing 64 bytes alone establishes
/// neither that width nor a valid field encoding.
///
/// Poseidon2 supports proving snapshot binding inside a circuit without SHA3
/// computation. Consumers must authenticate the snapshot and its activation
/// under the applicable transition rules. This value establishes no committee
/// authority, member eligibility, quorum or consensus finality, and a proposed
/// committee cannot authorize itself by supplying its identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitteeId([u8; 64]);

impl CommitteeId {
    /// The byte length of the encoded committee identifier.
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

impl TryFrom<&[u8]> for CommitteeId {
    type Error = CommitteeIdError;

    /// Copies a complete identifier from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`CommitteeIdError::InvalidByteLength`] if the slice does not
    /// contain exactly [`Self::BYTE_LENGTH`] bytes. Trailing bytes are rejected
    /// rather than ignored.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes
            .try_into()
            .map_err(|_| Self::Error::InvalidByteLength {
                actual: bytes.len(),
            })?;

        Ok(Self::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::{CommitteeId, CommitteeIdError};

    #[test]
    fn slice_conversion_preserves_complete_unverified_digests_in_order() {
        let patterned = std::array::from_fn::<_, 64, _>(|index| index as u8 ^ 0xa5);

        for bytes in [patterned, [0; 64], [u8::MAX; 64]] {
            let id = CommitteeId::try_from(bytes.as_slice()).unwrap();

            assert_eq!(id.as_bytes(), &bytes);
            assert_eq!(id.into_bytes(), bytes);
        }
    }

    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 32, 63, 65, 128] {
            let bytes = vec![0; length];

            assert!(matches!(
                CommitteeId::try_from(bytes.as_slice()),
                Err(CommitteeIdError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }
}
