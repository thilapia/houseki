//! Encoded public keys for ML-KEM-1024 recipient addresses.

mod error;

pub use error::EncodedMlKem1024PublicKeyError;

/// The complete encoded bytes of an ML-KEM-1024 public encapsulation key.
///
/// This value holds exactly 1568 bytes without interpreting or changing them.
/// Construction establishes the length only, so arbitrary byte patterns can
/// be represented even when they do not encode a valid key.
///
/// Before encapsulation, the cryptographic consumer must validate the key
/// under the selected suite. Address validation must also check its network,
/// format and recipient context. This type contains public material and does
/// not establish ownership, recipient identity or possession of a private key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncodedMlKem1024PublicKey([u8; 1568]);

impl EncodedMlKem1024PublicKey {
    /// The encoded byte length of an ML-KEM-1024 public encapsulation key.
    pub const BYTE_LENGTH: usize = 1568;

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

impl TryFrom<&[u8]> for EncodedMlKem1024PublicKey {
    type Error = EncodedMlKem1024PublicKeyError;

    /// Copies a complete encoded key from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`EncodedMlKem1024PublicKeyError::InvalidByteLength`] if the
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
    use super::{EncodedMlKem1024PublicKey, EncodedMlKem1024PublicKeyError};

    #[test]
    fn slice_conversion_preserves_all_bytes_in_order() {
        let bytes = std::array::from_fn::<_, 1568, _>(|index| (index % 251) as u8);
        let key = EncodedMlKem1024PublicKey::try_from(bytes.as_slice()).unwrap();

        assert_eq!(EncodedMlKem1024PublicKey::BYTE_LENGTH, 1568);
        assert_eq!(key.as_bytes(), &bytes);
        assert_eq!(key.into_bytes(), bytes);
    }

    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 1567, 1569, 3136] {
            let bytes = vec![0; length];

            assert!(matches!(
                EncodedMlKem1024PublicKey::try_from(bytes.as_slice()),
                Err(EncodedMlKem1024PublicKeyError::InvalidByteLength { actual })
                    if actual == length
            ));
        }
    }

    #[test]
    fn encoded_storage_preserves_bytes_without_claiming_key_validity() {
        for bytes in [[0; 1568], [u8::MAX; 1568]] {
            let key = EncodedMlKem1024PublicKey::from_bytes(bytes);
            let decoded = EncodedMlKem1024PublicKey::try_from(bytes.as_slice()).unwrap();

            assert_eq!(key, decoded);
            assert_eq!(key.into_bytes(), bytes);
        }
    }
}
