//! Bounded suite resolution from encrypted note payloads.

mod error;

pub use error::NotePayloadError;

use houseki_types::CryptoSuiteId;

use super::CryptoSuite;

impl CryptoSuite {
    /// Resolves a note payload's suite after checking its byte limit and minimum layout.
    ///
    /// The borrowed payload starts with a four byte little endian suite identifier, which V1
    /// follows with a 12 byte nonce and ciphertext ending in a 16 byte tag.
    ///
    /// An empty plaintext therefore requires 32 payload bytes, excluding the envelope's
    /// separate KEM encapsulation.
    ///
    /// Recovery uses this allocation free check to resolve output suites before constructing
    /// the typed core and encryption context.
    ///
    /// The caller supplies the active inclusive payload limit and remains responsible for
    /// bounding the original allocation, checking protocol activation and matching the suite
    /// to the intended output.
    ///
    /// Successful resolution establishes only the layout needed to attempt recovery, leaving
    /// authentication, algorithm message bounds and note validity to later checks.
    ///
    /// # Errors
    ///
    /// Rejects an excessive payload length before reading the header, then reports a truncated
    /// identifier or an unsupported suite without fallback.
    ///
    /// A recognized suite must also have room for its complete nonce and tag, with truncation
    /// errors reporting the required minimum payload length.
    pub fn from_note_payload(
        payload: &[u8],
        max_payload_bytes: usize,
    ) -> Result<Self, NotePayloadError> {
        if payload.len() > max_payload_bytes {
            return Err(NotePayloadError::PayloadLengthExceedsLimit {
                actual: payload.len(),
                maximum: max_payload_bytes,
            });
        }

        let (header, _) =
            payload
                .split_first_chunk::<4>()
                .ok_or(NotePayloadError::TruncatedPayload {
                    actual: payload.len(),
                    minimum: 4,
                })?;
        let suite = Self::try_from(CryptoSuiteId::new(u32::from_le_bytes(*header)))?;

        let minimum = match suite {
            Self::V1 => 4 + 12 + 16,
        };
        if payload.len() < minimum {
            return Err(NotePayloadError::TruncatedPayload {
                actual: payload.len(),
                minimum,
            });
        }

        Ok(suite)
    }
}

/// Payload limits, suite recognition and minimum layout boundaries.
#[cfg(test)]
mod tests {
    use houseki_types::{CryptoSuiteId, EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope};

    use crate::{CryptoSuite, CryptoSuiteError, NotePayloadError};

    /// Constructs opaque payload bytes with a complete suite header.
    fn payload(id: u32, length: usize) -> Vec<u8> {
        let mut bytes = vec![0xa5; length];
        bytes[..4].copy_from_slice(&id.to_le_bytes());

        bytes
    }

    /// Checks that the active byte limit takes precedence over format errors.
    #[test]
    fn payload_limits_are_checked_before_header_interpretation() {
        for bytes in [vec![0], payload(1, 31), payload(u32::MAX, 32)] {
            let actual = bytes.len();
            let maximum = actual - 1;

            assert!(matches!(
                CryptoSuite::from_note_payload(&bytes, maximum),
                Err(NotePayloadError::PayloadLengthExceedsLimit {
                    actual: reported,
                    maximum: limit,
                }) if reported == actual && limit == maximum
            ));
        }
    }

    /// Checks every incomplete suite identifier without attempting slice indexing.
    #[test]
    fn truncated_headers_require_four_bytes() {
        for actual in 0..4 {
            assert!(matches!(
                CryptoSuite::from_note_payload(&vec![0; actual], actual),
                Err(NotePayloadError::TruncatedPayload { actual: reported, minimum: 4 })
                    if reported == actual
            ));
        }
    }

    /// Checks complete unknown identifiers before applying any V1 layout assumptions.
    #[test]
    fn unsupported_suites_preserve_all_identifier_bits() {
        for id in [0, 2, 257, 65_537, 0x0100_0000, u32::MAX] {
            for length in [4, 16, 31, 32, 48] {
                assert!(matches!(
                    CryptoSuite::from_note_payload(&payload(id, length), length),
                    Err(NotePayloadError::UnsupportedSuite(CryptoSuiteError::Unsupported {
                        id: reported,
                    })) if reported == CryptoSuiteId::new(id)
                ));
            }
        }
    }

    /// Checks every missing nonce or tag byte in a recognized V1 payload.
    #[test]
    fn v1_requires_the_complete_nonce_and_tag() {
        for actual in 4..32 {
            assert!(matches!(
                CryptoSuite::from_note_payload(&payload(1, actual), actual),
                Err(NotePayloadError::TruncatedPayload { actual: reported, minimum: 32 })
                    if reported == actual
            ));
        }
    }

    /// Checks inclusive limits while leaving ciphertext and tag authentication to recovery.
    #[test]
    fn complete_layouts_resolve_without_authenticating_or_modifying_bytes() {
        for length in [32, 33, 48, 257] {
            let mut bytes = payload(1, length);
            for fill in [0, 0xa5, 0xff] {
                bytes[4..].fill(fill);
                let original = bytes.clone();

                assert_eq!(
                    CryptoSuite::from_note_payload(&bytes, length).unwrap(),
                    CryptoSuite::V1
                );
                assert_eq!(bytes, original);
            }
        }
    }

    /// Checks that an envelope accepted under an older limit is checked again during resolution.
    #[test]
    fn resolution_rechecks_the_active_envelope_payload_limit() {
        let envelope = EncryptedNoteEnvelope::new(
            EncodedMlKem1024Ciphertext::from_bytes([0; 1568]),
            payload(1, 48),
            48,
        )
        .unwrap();

        assert!(matches!(
            CryptoSuite::from_note_payload(envelope.payload(), 47),
            Err(NotePayloadError::PayloadLengthExceedsLimit {
                actual: 48,
                maximum: 47
            })
        ));
        assert_eq!(
            CryptoSuite::from_note_payload(envelope.payload(), 48).unwrap(),
            CryptoSuite::V1
        );
    }
}
