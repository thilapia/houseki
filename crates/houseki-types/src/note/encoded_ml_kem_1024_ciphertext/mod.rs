//! Encoded ML-KEM-1024 encapsulations carried by encrypted note envelopes.

mod error;

pub use error::EncodedMlKem1024CiphertextError;

/// The complete encoded bytes of an ML-KEM-1024 encapsulation ciphertext.
///
/// This value holds exactly 1568 bytes without interpreting or changing them.
///
/// It carries the encapsulation used to establish a shared secret, while the encrypted note
/// payload and its authentication material are separate parts of the note envelope.
///
/// Construction establishes the length only and preserves arbitrary byte patterns.
///
/// The recipient must perform decapsulation, key derivation and authenticated decryption under
/// the selected suite, then validate the recovered note and its context.
///
/// This value alone does not establish that the note can be recovered or belongs to the intended
/// recipient.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncodedMlKem1024Ciphertext(
    /// Complete encoded ML-KEM-1024 encapsulation ciphertext bytes.
    [u8; 1568],
);

impl EncodedMlKem1024Ciphertext {
    /// The encoded byte length of an ML-KEM-1024 encapsulation ciphertext.
    pub const BYTE_LENGTH: usize = 1568;

    /// Stores a complete encapsulation ciphertext without performing decapsulation.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the complete encoded encapsulation bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Consumes the value and returns its complete encoded encapsulation bytes.
    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for EncodedMlKem1024Ciphertext {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = EncodedMlKem1024CiphertextError;

    /// Copies a complete encapsulation from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`EncodedMlKem1024CiphertextError::InvalidByteLength`] if the slice does not
    /// contain exactly [`Self::BYTE_LENGTH`] bytes.
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

/// Construction, conversion and rejection properties of [`EncodedMlKem1024Ciphertext`].
#[cfg(test)]
mod tests {
    use super::{EncodedMlKem1024Ciphertext, EncodedMlKem1024CiphertextError};

    /// Checks that slice conversion preserves all bytes in order.
    #[test]
    fn slice_conversion_preserves_all_bytes_in_order() {
        let bytes = std::array::from_fn::<_, 1568, _>(|index| (index % 251) as u8);
        let ciphertext = EncodedMlKem1024Ciphertext::try_from(bytes.as_slice()).unwrap();

        assert_eq!(EncodedMlKem1024Ciphertext::BYTE_LENGTH, 1568);
        assert_eq!(ciphertext.as_bytes(), &bytes);
        assert_eq!(ciphertext.into_bytes(), bytes);
    }

    /// Checks that slice conversion rejects truncation and trailing bytes.
    #[test]
    fn slice_conversion_rejects_truncation_and_trailing_bytes() {
        for length in [0, 1, 1567, 1569, 3136] {
            let bytes = vec![0; length];

            assert!(matches!(
                EncodedMlKem1024Ciphertext::try_from(bytes.as_slice()),
                Err(EncodedMlKem1024CiphertextError::InvalidByteLength { actual })
                    if actual == length
            ));
        }
    }

    /// Checks that encoded storage preserves bytes without claiming note recovery.
    #[test]
    fn encoded_storage_preserves_bytes_without_claiming_note_recovery() {
        for bytes in [[0; 1568], [u8::MAX; 1568]] {
            let ciphertext = EncodedMlKem1024Ciphertext::from_bytes(bytes);
            let decoded = EncodedMlKem1024Ciphertext::try_from(bytes.as_slice()).unwrap();

            assert_eq!(ciphertext, decoded);
            assert_eq!(ciphertext.into_bytes(), bytes);
        }
    }
}
