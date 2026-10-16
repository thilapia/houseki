//! Encoded public keys for ML-DSA-87 reward withdrawal authority.

mod error;

pub use error::EncodedMlDsa87PublicKeyError;

/// The complete encoded bytes of an ML-DSA-87 public verification key.
///
/// This value holds exactly 2592 bytes without interpreting or changing them.
/// Construction establishes the length only and accepts every byte pattern.
///
/// A withdrawal consumer must check that the key matches the reward account's
/// immutable authority and verify the signature over the complete body and its
/// context outside proofs. Storing these public bytes does not establish private
/// key possession or authorize a withdrawal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncodedMlDsa87PublicKey([u8; 2592]);

impl EncodedMlDsa87PublicKey {
    /// The encoded byte length of an ML-DSA-87 public verification key.
    pub const BYTE_LENGTH: usize = 2592;

    /// Stores a complete encoded key without performing cryptographic validation.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the complete encoded key bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Consumes the value and returns its complete encoded key bytes.
    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for EncodedMlDsa87PublicKey {
    type Error = EncodedMlDsa87PublicKeyError;

    /// Copies a complete encoded key from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`EncodedMlDsa87PublicKeyError::InvalidByteLength`] if the
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
    use super::{EncodedMlDsa87PublicKey, EncodedMlDsa87PublicKeyError};

    #[test]
    fn slice_conversion_preserves_all_bytes_in_order() {
        let bytes = std::array::from_fn::<_, 2592, _>(|index| (index % 251) as u8);
        let key = EncodedMlDsa87PublicKey::try_from(bytes.as_slice()).unwrap();

        assert_eq!(key.as_bytes(), &bytes);
        assert_eq!(key.into_bytes(), bytes);
    }

    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 2591, 2593, 5184] {
            let bytes = vec![0; length];

            assert!(matches!(
                EncodedMlDsa87PublicKey::try_from(bytes.as_slice()),
                Err(EncodedMlDsa87PublicKeyError::InvalidByteLength { actual })
                    if actual == length
            ));
        }
    }

    #[test]
    fn encoded_storage_accepts_all_byte_patterns_without_authorizing_withdrawals() {
        for bytes in [[0; 2592], [u8::MAX; 2592]] {
            let key = EncodedMlDsa87PublicKey::from_bytes(bytes);
            let decoded = EncodedMlDsa87PublicKey::try_from(bytes.as_slice()).unwrap();

            assert_eq!(key, decoded);
            assert_eq!(key.into_bytes(), bytes);
        }
    }
}
