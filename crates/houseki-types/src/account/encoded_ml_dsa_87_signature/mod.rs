//! Encoded ML-DSA-87 signatures for reward withdrawals.

mod error;

pub use error::EncodedMlDsa87SignatureError;

/// The complete encoded bytes of an ML-DSA-87 signature.
///
/// This value holds exactly 4627 bytes without interpreting or changing them.
/// Construction establishes the length only, so arbitrary byte patterns can
/// be represented even when they do not encode a valid signature.
///
/// A withdrawal consumer must verify the signature outside proofs against the
/// reward account's immutable authority and the complete body and its context.
/// Storing these bytes does not establish canonical encoding, bind a message or
/// authorize a withdrawal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncodedMlDsa87Signature([u8; 4627]);

impl EncodedMlDsa87Signature {
    /// The encoded byte length of an ML-DSA-87 signature.
    pub const BYTE_LENGTH: usize = 4627;

    /// Stores a complete encoded signature without cryptographic validation.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the complete encoded signature bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Consumes the value and returns its complete encoded signature bytes.
    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for EncodedMlDsa87Signature {
    type Error = EncodedMlDsa87SignatureError;

    /// Copies a complete encoded signature from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`EncodedMlDsa87SignatureError::InvalidByteLength`] if the
    /// slice does not contain exactly [`Self::BYTE_LENGTH`] bytes. Trailing
    /// bytes are rejected rather than ignored.
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
    use super::{EncodedMlDsa87Signature, EncodedMlDsa87SignatureError};

    #[test]
    fn slice_conversion_preserves_all_bytes_in_order() {
        let bytes = std::array::from_fn::<_, 4627, _>(|index| (index % 251) as u8);
        let signature = EncodedMlDsa87Signature::try_from(bytes.as_slice()).unwrap();

        assert_eq!(signature.as_bytes(), &bytes);
        assert_eq!(signature.into_bytes(), bytes);
    }

    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 4626, 4628, 9254] {
            let bytes = vec![0; length];

            assert!(matches!(
                EncodedMlDsa87Signature::try_from(bytes.as_slice()),
                Err(EncodedMlDsa87SignatureError::InvalidByteLength { actual })
                    if actual == length
            ));
        }
    }

    #[test]
    fn encoded_storage_preserves_unverified_byte_patterns() {
        for bytes in [[0; 4627], [u8::MAX; 4627]] {
            let signature = EncodedMlDsa87Signature::from_bytes(bytes);
            let decoded = EncodedMlDsa87Signature::try_from(bytes.as_slice()).unwrap();

            assert_eq!(signature, decoded);
            assert_eq!(signature.into_bytes(), bytes);
        }
    }
}
