//! DAG vertex identifiers computed outside proofs.

mod error;

pub use error::VertexIdError;

/// A 64 byte SHA3-512 identifier of a DAG vertex.
///
/// Derivation runs outside proofs.
///
/// The dedicated domain, committed vertex fields and canonical encoding remain to be specified
/// with the consensus format.
///
/// This type stores the complete digest without computing it or checking that it matches a
/// vertex, and every byte pattern is representable.
///
/// Consumers must authenticate the vertex author and committee context and bind the complete
/// ordered payload to execution.
///
/// Possessing an identifier establishes neither that binding nor vertex validity, availability
/// or consensus finality.
///
/// Proofs may carry this identifier as data without computing SHA3 or Keccak.
///
/// The complete verifier must link that data to the authenticated vertex and the same ordered
/// occurrences whose execution is proved.
///
/// Carrying the identifier alone does not prove its derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VertexId(
    /// Complete declared vertex digest without payload authentication.
    [u8; 64],
);

impl VertexId {
    /// The byte length of the SHA3-512 vertex identifier.
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

impl TryFrom<&[u8]> for VertexId {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = VertexIdError;

    /// Copies a complete identifier from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`VertexIdError::InvalidByteLength`] if the slice does not contain exactly
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

/// Construction, conversion and rejection properties of [`VertexId`].
#[cfg(test)]
mod tests {
    use super::{VertexId, VertexIdError};

    /// Checks that slice conversion preserves every byte pattern in order.
    #[test]
    fn slice_conversion_preserves_every_byte_pattern_in_order() {
        let ordered = std::array::from_fn::<_, 64, _>(|index| index as u8);

        for bytes in [ordered, [0; 64], [u8::MAX; 64]] {
            let id = VertexId::try_from(bytes.as_slice()).unwrap();

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
                VertexId::try_from(bytes.as_slice()),
                Err(VertexIdError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }
}
