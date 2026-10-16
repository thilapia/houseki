//! Encapsulations and bounded opaque payloads for encrypted notes.

mod error;

pub use error::EncryptedNoteEnvelopeError;

use super::EncodedMlKem1024Ciphertext;

/// An ML-KEM-1024 encapsulation and an opaque encrypted note payload.
///
/// The payload holds the suite defined encoding of the encrypted note and its
/// authentication material, including any transmitted nonce. This type preserves
/// those bytes without choosing a KDF, authenticated encryption algorithm,
/// nonce or tag layout, padding scheme or wire encoding.
///
/// Construction checks only the payload length against a supplied inclusive
/// maximum. Empty payloads are representable because minimum lengths and framing
/// belong to the suite. Even a nonempty payload within the limit may be malformed
/// or unrecoverable. Consumers must resolve an allowed suite from the applicable
/// protocol context, validate its format and perform authenticated note recovery.
///
/// The maximum applies to payload bytes alone, excluding the fixed encapsulation
/// and any future framing. Callers must supply the active limit, enforce decoding
/// bounds before allocation and check total body size separately. A change in
/// limits requires checking the payload length again.
///
/// Transaction authorization must bind the complete envelope and its context.
/// Storing these bytes does not prove correct encryption or recipient delivery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptedNoteEnvelope {
    encapsulation: EncodedMlKem1024Ciphertext,
    payload: Vec<u8>,
}

impl EncryptedNoteEnvelope {
    /// Stores an encapsulation and payload under an inclusive payload byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`EncryptedNoteEnvelopeError::PayloadLengthExceedsLimit`] if the
    /// payload is longer than `max_payload_bytes`. A zero maximum permits only
    /// an empty payload and does not establish a usable encryption format.
    pub fn new(
        encapsulation: EncodedMlKem1024Ciphertext,
        payload: Vec<u8>,
        max_payload_bytes: usize,
    ) -> Result<Self, EncryptedNoteEnvelopeError> {
        if payload.len() > max_payload_bytes {
            return Err(EncryptedNoteEnvelopeError::PayloadLengthExceedsLimit {
                actual: payload.len(),
                maximum: max_payload_bytes,
            });
        }

        Ok(Self {
            encapsulation,
            payload,
        })
    }

    /// Borrows the complete encoded ML-KEM-1024 encapsulation.
    pub const fn encapsulation(&self) -> &EncodedMlKem1024Ciphertext {
        &self.encapsulation
    }

    /// Borrows the opaque payload without interpreting its contents.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the actual payload length, excluding encapsulation and framing.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Consumes the envelope and returns its encapsulation and complete payload.
    pub fn into_parts(self) -> (EncodedMlKem1024Ciphertext, Vec<u8>) {
        (self.encapsulation, self.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::{EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope, EncryptedNoteEnvelopeError};

    #[test]
    fn construction_preserves_complete_bytes_at_the_payload_limit() {
        let bytes = std::array::from_fn(|index| (index % 251) as u8);
        let encapsulation = EncodedMlKem1024Ciphertext::from_bytes(bytes);
        let payload: Vec<u8> = (0..=u8::MAX).rev().collect();
        let envelope =
            EncryptedNoteEnvelope::new(encapsulation.clone(), payload.clone(), payload.len())
                .unwrap();

        assert_eq!(envelope.encapsulation().as_bytes(), &bytes);
        assert_eq!(envelope.payload(), payload.as_slice());
        assert_eq!(envelope.payload_len(), payload.len());
        assert_eq!(envelope.into_parts(), (encapsulation, payload));
    }

    #[test]
    fn construction_rejects_payloads_above_the_supplied_limit() {
        for (actual, maximum) in [(1, 0), (2, 1), (257, 256)] {
            let result = EncryptedNoteEnvelope::new(
                EncodedMlKem1024Ciphertext::from_bytes([0; 1568]),
                vec![0; actual],
                maximum,
            );

            assert!(matches!(
                result,
                Err(EncryptedNoteEnvelopeError::PayloadLengthExceedsLimit {
                    actual: reported_actual, maximum: reported_maximum,
                }) if reported_actual == actual && reported_maximum == maximum
            ));
        }
    }

    #[test]
    fn construction_leaves_payload_format_validation_to_the_suite() {
        for (payload, maximum) in [
            (vec![], 0),
            (vec![], 1),
            (vec![0], 1),
            (vec![u8::MAX; 3], 4),
            (vec![0], usize::MAX),
        ] {
            let envelope = EncryptedNoteEnvelope::new(
                EncodedMlKem1024Ciphertext::from_bytes([u8::MAX; 1568]),
                payload.clone(),
                maximum,
            )
            .unwrap();

            assert_eq!(envelope.payload(), payload.as_slice());
        }
    }
}
