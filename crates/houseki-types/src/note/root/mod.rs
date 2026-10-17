//! Encoded roots of the note commitment tree.

mod error;

pub use error::NoteRootError;

/// The 64 byte digest representation of a note commitment tree root.
///
/// A spending proof checks note membership against this root and binds the original leaf
/// position to nullifier derivation.
///
/// Execution must separately establish that the root belongs to the allowed finalized anchor
/// history for the checkpoint.
///
/// Membership alone does not establish that a note is unspent.
///
/// This value preserves arbitrary bytes without computing the tree or checking membership,
/// finality or anchor eligibility.
///
/// It is distinct from a note commitment and from roots of other state components.
///
/// A note root alone does not authenticate reward accounts, the spent set or the complete ledger
/// state.
///
/// The proposed root hash profile uses Poseidon2 with 512 effective digest bits.
///
/// Tree shape, capacity, leaf and internal node domains, empty tree derivation and canonical
/// output conversion remain to be specified.
///
/// A 64 byte container does not establish the effective width or security of that profile, and
/// no byte pattern is assigned the meaning of an empty tree by this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoteRoot(
    /// Complete declared note tree digest without anchor eligibility evidence.
    [u8; 64],
);

impl NoteRoot {
    /// The byte length of the encoded note tree root digest.
    pub const BYTE_LENGTH: usize = 64;

    /// Stores a complete note tree root without verifying its derivation.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the complete note tree root bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Consumes the value and returns its complete note tree root bytes.
    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for NoteRoot {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = NoteRootError;

    /// Copies a complete note tree root from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`NoteRootError::InvalidByteLength`] if the slice does not contain exactly
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

/// Construction, conversion and rejection properties of [`NoteRoot`].
#[cfg(test)]
mod tests {
    use super::{NoteRoot, NoteRootError};

    /// Checks that slice conversion preserves complete unverified digests in order.
    #[test]
    fn slice_conversion_preserves_complete_unverified_digests_in_order() {
        let patterned = std::array::from_fn::<_, 64, _>(|index| index as u8 ^ 0xa5);

        for bytes in [patterned, [0; 64], [u8::MAX; 64]] {
            let root = NoteRoot::try_from(bytes.as_slice()).unwrap();

            assert_eq!(root.as_bytes(), &bytes);
            assert_eq!(root.into_bytes(), bytes);
            assert_eq!(root, NoteRoot::from_bytes(bytes));
        }
    }

    /// Checks that slice conversion rejects truncation and trailing bytes.
    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 32, 63, 65, 128] {
            let bytes = vec![0; length];

            assert!(matches!(
                NoteRoot::try_from(bytes.as_slice()),
                Err(NoteRootError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }
}
