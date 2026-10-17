//! Encoded public markers used to prevent repeated note spending.

mod error;

pub use error::NullifierError;

/// The 64 byte digest representation of a note instance's public spend marker.
///
/// The Poseidon2 derivation must bind the note's prescribed nullifier key, commitment and
/// original [`super::NotePosition`].
///
/// The spending proof must connect that position to proven membership, so changing the anchor or
/// proof randomness cannot give the same note instance another usable nullifier.
///
/// Execution checks that input nullifiers are pairwise distinct and absent from the evolving
/// spent set.
///
/// It records them only when the transaction occurrence succeeds atomically.
///
/// A rejected occurrence must not reserve its nullifiers.
///
/// This value preserves arbitrary bytes without deriving the nullifier or verifying
/// authorization, membership or unspentness.
///
/// The hash profile must provide 512 effective digest bits, with its field, permutation
/// parameters, capacity, domains and output conversion still to be specified.
///
/// Merely storing 64 bytes does not establish that requirement or a security level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullifier(
    /// Complete declared spend marker without derivation or spent set evidence.
    [u8; 64],
);

impl Nullifier {
    /// The byte length of the encoded nullifier digest.
    pub const BYTE_LENGTH: usize = 64;

    /// Stores a complete nullifier without verifying its derivation.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the complete nullifier bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Consumes the value and returns its complete nullifier bytes.
    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for Nullifier {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = NullifierError;

    /// Copies a complete nullifier from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`NullifierError::InvalidByteLength`] if the slice does not contain exactly
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

/// Construction, conversion and rejection properties of [`Nullifier`].
#[cfg(test)]
mod tests {
    use super::{Nullifier, NullifierError};

    /// Checks that slice conversion preserves complete unverified digests in order.
    #[test]
    fn slice_conversion_preserves_complete_unverified_digests_in_order() {
        let patterned = std::array::from_fn::<_, 64, _>(|index| index as u8 ^ 0xa5);

        for bytes in [patterned, [0; 64], [u8::MAX; 64]] {
            let nullifier = Nullifier::try_from(bytes.as_slice()).unwrap();

            assert_eq!(nullifier.as_bytes(), &bytes);
            assert_eq!(nullifier.into_bytes(), bytes);
            assert_eq!(nullifier, Nullifier::from_bytes(bytes));
        }
    }

    /// Checks that slice conversion rejects truncation and trailing bytes.
    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 32, 63, 65, 128] {
            let bytes = vec![0; length];

            assert!(matches!(
                Nullifier::try_from(bytes.as_slice()),
                Err(NullifierError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }
}
