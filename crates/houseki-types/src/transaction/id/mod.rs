//! Semantic transaction identifiers computed outside proofs.

mod error;

pub use error::TransactionIdError;

/// A 64 byte SHA3-512 identifier of the canonical transaction body and kind.
///
/// Derivation runs outside proofs under a dedicated domain and canonical body encoding, which
/// remain to be specified.
///
/// The body includes its context and complete ordered effects, including encrypted note
/// envelopes.
///
/// Proof and signature bytes are excluded, so regenerating authorization for the same body does
/// not change its identifier.
///
/// This type stores the complete digest without computing it or checking that it matches a body.
///
/// Every byte pattern is representable.
///
/// Construction does not establish transaction validity, authorization, execution or finality,
/// and replay protection still relies on nullifiers and account nonces.
///
/// This native identifier is separate from any effect digest computed inside a proof.
///
/// Its use must not require SHA3 or Keccak computation in the circuit or substitute an
/// unverified identifier for binding the actual body effects.
///
/// DAG payload commitments separately cover complete envelopes, including their proof bytes,
/// order and multiplicity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId(
    /// Complete declared body digest without derivation or authorization evidence.
    [u8; 64],
);

impl TransactionId {
    /// The byte length of the SHA3-512 transaction identifier.
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

impl TryFrom<&[u8]> for TransactionId {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = TransactionIdError;

    /// Copies a complete identifier from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionIdError::InvalidByteLength`] if the slice does not contain exactly
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

/// Construction, conversion and rejection properties of [`TransactionId`].
#[cfg(test)]
mod tests {
    use super::{TransactionId, TransactionIdError};

    /// Checks that slice conversion preserves the complete digest in order.
    #[test]
    fn slice_conversion_preserves_the_complete_digest_in_order() {
        let bytes = std::array::from_fn::<_, 64, _>(|index| index as u8);
        let id = TransactionId::try_from(bytes.as_slice()).unwrap();

        assert_eq!(TransactionId::BYTE_LENGTH, 64);
        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.into_bytes(), bytes);
    }

    /// Checks that slice conversion rejects truncation and trailing bytes.
    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 32, 63, 65, 128] {
            let bytes = vec![0; length];

            assert!(matches!(
                TransactionId::try_from(bytes.as_slice()),
                Err(TransactionIdError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }

    /// Checks that construction preserves unverified digest bytes.
    #[test]
    fn construction_preserves_unverified_digest_bytes() {
        for bytes in [[0; 64], [u8::MAX; 64]] {
            let id = TransactionId::from_bytes(bytes);
            let decoded = TransactionId::try_from(bytes.as_slice()).unwrap();

            assert_eq!(id, decoded);
            assert_eq!(id.into_bytes(), bytes);
        }
    }
}
