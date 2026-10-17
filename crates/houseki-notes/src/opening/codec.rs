//! Private canonical plaintext encoding and parsing without authentication or commitment claims.
//!
//! V1 contains a four byte little endian version, a sixteen byte little endian atom count
//! and 32 blinding bytes, without padding or trailing fields.

use super::{NoteOpening, NotePlaintextError};
use crate::{NoteBlinding, NoteFormat, NoteRecipient};
use houseki_types::{Amount, NoteVersion};
use zeroize::Zeroizing;

/// Exact length of the initial private record without padding or trailing fields.
const PLAINTEXT_LENGTH: usize = 52;

/// First amount byte after the complete immutable note version.
const AMOUNT_OFFSET: usize = 4;

/// First blinding byte after the complete private amount encoding.
const BLINDING_OFFSET: usize = 20;

impl NoteOpening {
    /// Encodes the selected immutable format into guarded private plaintext storage.
    ///
    /// The caller retains the returned owner through sealing, with no unguarded vector or
    /// public secret export created by this internal operation.
    pub(crate) fn encode_plaintext(&self) -> Zeroizing<[u8; PLAINTEXT_LENGTH]> {
        match self.format() {
            NoteFormat::V1 => {
                let mut plaintext = Zeroizing::new([0; PLAINTEXT_LENGTH]);
                plaintext[..AMOUNT_OFFSET]
                    .copy_from_slice(&self.format().version().value().to_le_bytes());

                let amount_bytes = Zeroizing::new(self.amount().to_le_bytes());
                plaintext[AMOUNT_OFFSET..BLINDING_OFFSET].copy_from_slice(&amount_bytes[..]);
                plaintext[BLINDING_OFFSET..].copy_from_slice(self.blinding.as_bytes());

                plaintext
            }
        }
    }

    /// Parses storage invariants while retaining the supplied expected recipient snapshot.
    ///
    /// The caller keeps the source plaintext in guarded storage through parsing and must
    /// authenticate it and match its commitment before any public recovery result is returned.
    ///
    /// This private operation establishes neither authentication nor commitment agreement.
    ///
    /// # Errors
    ///
    /// Rejects inexact length first, then unsupported full note versions, excessive amounts
    /// and finally zero amounts through the existing opening constructor.
    ///
    /// Owned private decoding buffers are guarded through success, failure and unwinding,
    /// with original input storage remaining under the caller's cleanup responsibility.
    pub(crate) fn decode_plaintext(
        plaintext: &[u8],
        recipient: &NoteRecipient,
    ) -> Result<Self, NotePlaintextError> {
        let plaintext: &[u8; PLAINTEXT_LENGTH] =
            plaintext
                .try_into()
                .map_err(|_| NotePlaintextError::InvalidLength {
                    actual: plaintext.len(),
                })?;

        let version = NoteVersion::new(u32::from_le_bytes([
            plaintext[0],
            plaintext[1],
            plaintext[2],
            plaintext[3],
        ]));
        let format = NoteFormat::try_from(version)?;

        // Each added format must select its own plaintext layout.
        match format {
            NoteFormat::V1 => {}
        }

        let mut amount_bytes = Zeroizing::new([0; 16]);
        amount_bytes.copy_from_slice(&plaintext[AMOUNT_OFFSET..BLINDING_OFFSET]);
        let atoms = Zeroizing::new(u128::from_le_bytes(*amount_bytes));
        let amount = Zeroizing::new(Amount::from_atoms(*atoms)?);

        let mut blinding_bytes = Zeroizing::new([0; NoteBlinding::LENGTH]);
        blinding_bytes.copy_from_slice(&plaintext[BLINDING_OFFSET..]);
        let blinding = NoteBlinding::from_bytes(&blinding_bytes);

        Self::new(format, recipient, *amount, blinding).map_err(Into::into)
    }
}

/// Canonical private bytes, bounded parsing, protected retention and recipient context scope.
#[cfg(test)]
mod tests {
    use crate::{
        NoteBlinding, NoteFormat, NoteFormatError, NoteOpening, NoteOpeningError, NoteRecipient,
        opening::NotePlaintextError,
    };
    use houseki_crypto::CryptoSuite;
    use houseki_types::{
        AddressContext, AddressFormatVersion, Amount, AmountError, EncodedMlKem1024PublicKey,
        NetworkId, NoteVersion, OwnershipCommitment, RecipientDescriptor,
    };
    use zeroize::Zeroizing;

    /// Builds checked recipients with one network and differing ownership and public key seed.
    fn recipient(pattern: u8) -> NoteRecipient {
        let network = NetworkId::from_bytes([7; 64]);
        let context =
            AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id());

        let mut key = [0; 1568];
        key[1536..].fill(pattern);

        let descriptor = RecipientDescriptor::new(
            context,
            OwnershipCommitment::from_bytes([pattern; 64]),
            EncodedMlKem1024PublicKey::from_bytes(key),
        );

        NoteRecipient::validate(&descriptor, network).unwrap()
    }

    /// Assembles deterministic records independently of the codec's field offsets.
    fn plaintext(atoms: u128, blinding: &[u8; 32]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            [
                vec![1, 0, 0, 0],
                atoms.to_le_bytes().to_vec(),
                blinding.to_vec(),
            ]
            .concat(),
        )
    }

    /// Checks the complete encoded record with literal amount bytes and preserved source material.
    #[test]
    fn encoding_matches_the_exact_private_record_without_consuming_the_opening() {
        let recipient = recipient(0xa7);
        let atoms = 0x0102_0304_0506_0708_090a_0b0c;
        let amount = Amount::from_atoms(atoms).unwrap();
        let blinding = NoteBlinding::generate().unwrap();
        let expected = Zeroizing::new(
            [
                vec![1, 0, 0, 0],
                vec![12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0],
                blinding.as_bytes().to_vec(),
            ]
            .concat(),
        );
        let opening = NoteOpening::new(NoteFormat::V1, &recipient, amount, blinding).unwrap();

        let encoded: Zeroizing<[u8; 52]> = opening.encode_plaintext();

        assert_eq!(&encoded[..], &expected[..]);
        assert_eq!(opening.amount().atoms(), atoms);
        assert_eq!(opening.recipient(), &recipient);
        assert_eq!(&opening.blinding.as_bytes()[..], &expected[20..]);
    }

    /// Checks positive boundaries and all blinding patterns survive parsing and canonical reencoding.
    #[test]
    fn decoding_retains_positive_amounts_and_complete_blinding_patterns() {
        let recipient = recipient(0x35);

        for atoms in [1, 1_u128 << 64, Amount::MAX_ATOMS] {
            for blinding in [
                [0; 32],
                [0xff; 32],
                std::array::from_fn(|index| index as u8),
            ] {
                let bytes = plaintext(atoms, &blinding);

                let opening = NoteOpening::decode_plaintext(&bytes, &recipient).unwrap();

                assert_eq!(opening.format(), NoteFormat::V1);
                assert_eq!(opening.amount().atoms(), atoms);
                assert_eq!(opening.recipient(), &recipient);
                assert_eq!(opening.blinding.as_bytes(), &blinding);
                assert_eq!(&opening.encode_plaintext()[..], &bytes[..]);
            }
        }
    }

    /// Checks every truncated prefix and trailing records before interpreting private fields.
    #[test]
    fn decoding_rejects_inexact_lengths_before_version_and_amount_checks() {
        let recipient = recipient(0x59);
        let bytes = Zeroizing::new(vec![0xff; 52]);

        for length in 0..52 {
            assert!(matches!(
                NoteOpening::decode_plaintext(&bytes[..length], &recipient),
                Err(NotePlaintextError::InvalidLength { actual }) if actual == length
            ));
        }

        for length in [53, 104] {
            let bytes = Zeroizing::new(vec![0xff; length]);

            assert!(matches!(
                NoteOpening::decode_plaintext(&bytes, &recipient),
                Err(NotePlaintextError::InvalidLength { actual }) if actual == length
            ));
        }
    }

    /// Checks unsupported full version identifiers precede excessive private amount decoding.
    #[test]
    fn decoding_preserves_all_version_bits_before_amount_validation() {
        let recipient = recipient(0x17);
        let mut bytes = plaintext(u128::MAX, &[0xff; 32]);

        for value in [0, 2, 257, 65_537, 0x0100_0001, u32::MAX] {
            bytes[..4].copy_from_slice(&value.to_le_bytes());

            assert!(matches!(
                NoteOpening::decode_plaintext(&bytes, &recipient),
                Err(NotePlaintextError::UnsupportedFormat(NoteFormatError::Unsupported { version }))
                    if version == NoteVersion::new(value)
            ));
        }
    }

    /// Checks zero and excessive amounts return only errors without private values or openings.
    #[test]
    fn decoding_rejects_zero_and_amounts_above_the_cap() {
        let recipient = recipient(0xc3);
        let zero = plaintext(0, &[0xa5; 32]);

        assert!(matches!(
            NoteOpening::decode_plaintext(&zero, &recipient),
            Err(NotePlaintextError::InvalidOpening(
                NoteOpeningError::ZeroAmount
            ))
        ));

        for atoms in [Amount::MAX_ATOMS + 1, 1_u128 << 127, u128::MAX] {
            let bytes = plaintext(atoms, &[0x3c; 32]);

            let error = NoteOpening::decode_plaintext(&bytes, &recipient).unwrap_err();

            assert!(matches!(
                error,
                NotePlaintextError::InvalidAmount(AmountError::ValueExceedsMaximum)
            ));
            assert_eq!(
                error.to_string(),
                "the amount exceeds the maximum allowed value"
            );
        }
    }

    /// Checks parsing retains the supplied owned snapshot without asserting commitment binding.
    #[test]
    fn decoding_owns_the_expected_recipient_without_authenticating_its_binding() {
        let first = recipient(0x47);
        let second = recipient(0xb9);
        let bytes = plaintext(1, &[0x7e; 32]);
        let opening = {
            let source = first.clone();

            NoteOpening::decode_plaintext(&bytes, &source).unwrap()
        };

        let other = NoteOpening::decode_plaintext(&bytes, &second).unwrap();

        assert_eq!(opening.recipient(), &first);
        assert_eq!(other.recipient(), &second);
        assert_ne!(opening.recipient(), other.recipient());
        assert_eq!(
            &opening.encode_plaintext()[..],
            &other.encode_plaintext()[..]
        );
    }
}
