//! Encoded Poseidon2 note commitments.

mod error;

pub use error::NoteCommitmentError;

/// The 64 byte digest representation of a Poseidon2 note commitment.
///
/// The note hash profile must provide 512 effective digest bits. This value
/// stores the resulting bytes without computing the commitment or validating
/// its relationship to a note opening. Every byte pattern is representable,
/// and construction checks neither membership nor spending authority.
///
/// The selected field, permutation parameters, sponge capacity, domain framing
/// and conversion of field outputs to digest bytes remain to be specified.
/// Serializing field elements into 64 bytes does not by itself meet the
/// effective width requirement or establish a security level.
///
/// Equal commitments do not identify the same inserted note instance. Nullifier
/// derivation also binds the original [`super::NotePosition`] and the note's
/// prescribed nullifier key. Consumers must verify the opening, membership
/// and position binding under the selected note rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoteCommitment([u8; 64]);

impl NoteCommitment {
    /// The byte length of the encoded note commitment digest.
    pub const BYTE_LENGTH: usize = 64;

    /// Stores a complete commitment without verifying its derivation.
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

impl TryFrom<&[u8]> for NoteCommitment {
    type Error = NoteCommitmentError;

    /// Copies a complete commitment from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`NoteCommitmentError::InvalidByteLength`] if the slice does not
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
    use super::{NoteCommitment, NoteCommitmentError};

    #[test]
    fn slice_conversion_preserves_complete_unverified_digests_in_order() {
        let patterned = std::array::from_fn::<_, 64, _>(|index| index as u8 ^ 0xa5);

        for bytes in [patterned, [0; 64], [u8::MAX; 64]] {
            let commitment = NoteCommitment::try_from(bytes.as_slice()).unwrap();

            assert_eq!(commitment.as_bytes(), &bytes);
            assert_eq!(commitment.into_bytes(), bytes);
            assert_eq!(commitment, NoteCommitment::from_bytes(bytes));
        }
    }

    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 32, 63, 65, 128] {
            let bytes = vec![0; length];

            assert!(matches!(
                NoteCommitment::try_from(bytes.as_slice()),
                Err(NoteCommitmentError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }
}
