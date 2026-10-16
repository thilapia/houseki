//! Canonical binary payload encoding and checked decoding for recipient descriptors.

use houseki_types::{
    AddressContext, AddressFormatVersion, CryptoSuiteId, EncodedMlKem1024PublicKey, NetworkId,
    OwnershipCommitment, RecipientDescriptor,
};

use super::{NoteRecipient, NoteRecipientError, validate_address_format};

/// First network byte after the complete address format identifier.
const NETWORK_OFFSET: usize = 4;

/// First suite byte after the complete network identifier.
const SUITE_OFFSET: usize = 68;

/// First ownership byte after the complete suite identifier.
const OWNERSHIP_OFFSET: usize = 72;

/// First public key byte after the complete ownership commitment.
const KEY_OFFSET: usize = 136;

impl NoteRecipient {
    /// Exact byte length of the supported address format 1 binary descriptor payload.
    pub const BINARY_LENGTH: usize = 1704;

    /// Decodes the complete binary payload and checks it against the intended network.
    ///
    /// Format 1 contains a four byte little endian address version, 64 network bytes, a four
    /// byte little endian suite identifier, 64 ownership bytes and the complete 1568 byte
    /// canonical ML-KEM-1024 public key, without padding or trailing data.
    ///
    /// Decoding borrows the bounded input before constructing declared fields and reusing
    /// [`Self::validate`], with no text, checksum, provenance or ownership proof check.
    ///
    /// # Errors
    ///
    /// Reports [`NoteRecipientError::InvalidBinaryLength`] before reading any field, then
    /// [`NoteRecipientError::UnsupportedAddressFormat`] before interpreting the remaining layout.
    ///
    /// After layout recognition, typed validation checks network, suite and canonical key
    /// encoding in its existing order and preserves their original errors.
    pub fn from_bytes(
        bytes: &[u8],
        expected_network: NetworkId,
    ) -> Result<Self, NoteRecipientError> {
        let bytes: &[u8; Self::BINARY_LENGTH] =
            bytes
                .try_into()
                .map_err(|_| NoteRecipientError::InvalidBinaryLength {
                    actual: bytes.len(),
                })?;
        let version =
            AddressFormatVersion::new(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        validate_address_format(version)?;

        let network =
            NetworkId::from_bytes(std::array::from_fn(|index| bytes[NETWORK_OFFSET + index]));
        let suite = CryptoSuiteId::new(u32::from_le_bytes([
            bytes[SUITE_OFFSET],
            bytes[SUITE_OFFSET + 1],
            bytes[SUITE_OFFSET + 2],
            bytes[SUITE_OFFSET + 3],
        ]));
        let context = AddressContext::new(network, version, suite);
        let ownership = OwnershipCommitment::from_bytes(std::array::from_fn(|index| {
            bytes[OWNERSHIP_OFFSET + index]
        }));
        let key = EncodedMlKem1024PublicKey::from_bytes(std::array::from_fn(|index| {
            bytes[KEY_OFFSET + index]
        }));
        let descriptor = RecipientDescriptor::new(context, ownership, key);

        Self::validate(&descriptor, expected_network)
    }

    /// Encodes the complete checked recipient as the canonical binary descriptor payload.
    ///
    /// The fixed array retains every context, ownership and canonical public key byte in
    /// format 1 order, without selecting a text representation or checksum.
    pub fn to_bytes(&self) -> [u8; Self::BINARY_LENGTH] {
        let context = self.context();
        let mut bytes = [0; Self::BINARY_LENGTH];
        bytes[..NETWORK_OFFSET].copy_from_slice(&context.format_version().value().to_le_bytes());
        bytes[NETWORK_OFFSET..SUITE_OFFSET].copy_from_slice(context.network_id().as_bytes());
        bytes[SUITE_OFFSET..OWNERSHIP_OFFSET]
            .copy_from_slice(&context.crypto_suite_id().value().to_le_bytes());
        bytes[OWNERSHIP_OFFSET..KEY_OFFSET].copy_from_slice(self.ownership_commitment().as_bytes());
        bytes[KEY_OFFSET..].copy_from_slice(self.kem_public_key().to_encoded().as_bytes());

        bytes
    }
}

/// Complete byte fixtures, exact length bounds and binary parsing error precedence.
#[cfg(test)]
mod tests {
    use houseki_crypto::{CryptoSuite, CryptoSuiteError, MlKem1024EncapsulationKeyError};
    use houseki_types::{
        AddressContext, AddressFormatVersion, CryptoSuiteId, EncodedMlKem1024PublicKey, NetworkId,
        OwnershipCommitment, RecipientDescriptor,
    };

    use crate::{NoteRecipient, NoteRecipientError};

    /// Builds a network with distinct bytes at every encoded position.
    fn network() -> NetworkId {
        NetworkId::from_bytes(std::array::from_fn(|index| index as u8))
    }

    /// Builds boundary polynomial coefficients followed by distinct unrestricted seed bytes.
    fn key() -> EncodedMlKem1024PublicKey {
        let mut bytes = [0; 1568];
        for pair in bytes[..1536].as_chunks_mut::<3>().0 {
            pair.copy_from_slice(&[0x00, 0x0d, 0xd0]);
        }
        bytes[1536..].copy_from_slice(&std::array::from_fn::<_, 32, _>(|index| 0xc0 + index as u8));

        EncodedMlKem1024PublicKey::from_bytes(bytes)
    }

    /// Builds declared fields independently of the binary codec.
    fn descriptor() -> RecipientDescriptor {
        let context = AddressContext::new(
            network(),
            AddressFormatVersion::new(1),
            CryptoSuite::V1.id(),
        );
        let ownership =
            OwnershipCommitment::from_bytes(std::array::from_fn(|index| 0x40 + index as u8));

        RecipientDescriptor::new(context, ownership, key())
    }

    /// Assembles the complete specified byte sequence without invoking the codec or its offsets.
    fn canonical_bytes() -> [u8; 1704] {
        [
            vec![1, 0, 0, 0],
            (0_u8..64).collect(),
            vec![1, 0, 0, 0],
            (64_u8..128).collect(),
            key().as_bytes().to_vec(),
        ]
        .concat()
        .try_into()
        .unwrap()
    }

    /// Checks every encoded field against an independent complete fixture and checked snapshot.
    #[test]
    fn binary_codec_matches_the_complete_canonical_fixture() {
        let descriptor = descriptor();
        let expected = NoteRecipient::validate(&descriptor, network()).unwrap();
        let bytes = canonical_bytes();

        assert_eq!(NoteRecipient::BINARY_LENGTH, 1704);
        assert_eq!(expected.to_bytes(), bytes);
        assert_eq!(
            NoteRecipient::from_bytes(&bytes, network()).unwrap(),
            expected
        );
        assert_eq!(
            NoteRecipient::from_bytes(&expected.to_bytes(), network()).unwrap(),
            expected
        );
    }

    /// Checks every truncated prefix and trailing records before format or context interpretation.
    #[test]
    fn binary_decoding_rejects_inexact_lengths_before_reading_fields() {
        let mut bytes = canonical_bytes();
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        let wrong_network = NetworkId::from_bytes([0xff; 64]);

        for length in 0..1704 {
            assert!(matches!(
                NoteRecipient::from_bytes(&bytes[..length], wrong_network),
                Err(NoteRecipientError::InvalidBinaryLength { actual }) if actual == length
            ));
        }
        for length in [1705, 1720, 3408] {
            let mut trailing = bytes.to_vec();
            trailing.resize(length, 0xa5);

            assert!(matches!(
                NoteRecipient::from_bytes(&trailing, wrong_network),
                Err(NoteRecipientError::InvalidBinaryLength { actual }) if actual == length
            ));
        }
    }

    /// Checks complete unsupported versions before fields whose layout has not been recognized.
    #[test]
    fn binary_format_recognition_precedes_context_and_key_checks() {
        let mut bytes = canonical_bytes();
        bytes[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[136..139].fill(0xff);
        let wrong_network = NetworkId::from_bytes([0xff; 64]);

        for value in [0, 2, 257, 65_537, 0x0100_0001, u32::MAX] {
            bytes[..4].copy_from_slice(&value.to_le_bytes());

            assert!(matches!(
                NoteRecipient::from_bytes(&bytes, wrong_network),
                Err(NoteRecipientError::UnsupportedAddressFormat { version })
                    if version == AddressFormatVersion::new(value)
            ));
        }
    }

    /// Checks every network byte and its precedence over an unsupported suite and invalid key.
    #[test]
    fn binary_network_validation_retains_all_bytes_before_later_checks() {
        for index in 0..64 {
            let mut bytes = canonical_bytes();
            bytes[4 + index] ^= 0x80;
            bytes[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
            bytes[136..139].fill(0xff);
            let mut actual = *network().as_bytes();
            actual[index] ^= 0x80;

            assert!(matches!(
                NoteRecipient::from_bytes(&bytes, network()),
                Err(NoteRecipientError::NetworkMismatch { actual: reported })
                    if reported == NetworkId::from_bytes(actual)
            ));
        }
    }

    /// Checks complete suite identifiers are preserved before canonical public key validation.
    #[test]
    fn binary_suite_resolution_precedes_key_import_without_narrowing() {
        let mut bytes = canonical_bytes();
        bytes[136..139].fill(0xff);
        for value in [0, 2, 257, 65_537, 0x0100_0001, u32::MAX] {
            bytes[68..72].copy_from_slice(&value.to_le_bytes());

            assert!(matches!(
                NoteRecipient::from_bytes(&bytes, network()),
                Err(NoteRecipientError::UnsupportedSuite(CryptoSuiteError::Unsupported { id }))
                    if id == CryptoSuiteId::new(value)
            ));
        }
    }

    /// Checks both coefficient packing halves at either end retain the original crypto error.
    #[test]
    fn binary_noncanonical_keys_preserve_the_import_failure() {
        for offset in [136, 1669] {
            for pair in [[0x01, 0x0d, 0x00], [0x00, 0x10, 0xd0]] {
                let mut bytes = canonical_bytes();
                bytes[offset..offset + 3].copy_from_slice(&pair);

                assert!(matches!(
                    NoteRecipient::from_bytes(&bytes, network()),
                    Err(NoteRecipientError::InvalidEncapsulationKey(
                        MlKem1024EncapsulationKeyError::NonCanonicalEncoding
                    ))
                ));
            }
        }
    }
}
