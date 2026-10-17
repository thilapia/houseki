//! Checked public recipient snapshots for private note construction and recovery.

mod codec;
mod error;
mod text;

pub use error::NoteRecipientError;
pub use text::NoteAddressError;

use houseki_crypto::{CryptoSuite, MlKem1024EncapsulationKey};
use houseki_types::{
    AddressContext, AddressFormatVersion, NetworkId, OwnershipCommitment, RecipientDescriptor,
};

/// An immutable recipient descriptor checked against its intended network and address rules.
///
/// Address format 1 supports only [`CryptoSuite::V1`] and requires a complete canonical
/// ML-KEM-1024 public key, retaining the declared ownership commitment beside that validated key.
///
/// Validation imports the public key into owned storage and copies the public context and
/// ownership digest, so the snapshot does not borrow the original descriptor.
///
/// The ownership digest remains declared data, and validation establishes neither its secret
/// opening nor honest key generation, decryption capability, provenance or spending authority.
///
/// [`Self::from_bytes`] checks the canonical binary descriptor payload, while [`Self::to_bytes`]
/// encodes the retained public fields without a text alphabet or checksum.
///
/// [`Self::to_address`] and [`Self::from_address`] provide the canonical complete text and
/// transcription checksum, while opening construction checks compatibility with its note format.
///
/// Commitment consumers derive recipient binding internally through crypto from this snapshot's
/// network, suite and key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteRecipient {
    /// Address context checked for the intended network and supported identifiers.
    context: AddressContext,

    /// Recognized suite allowed by the address format.
    suite: CryptoSuite,

    /// Declared ownership digest retained without proving its secret opening.
    ownership_commitment: OwnershipCommitment,

    /// Owned public encapsulation key with a validated canonical encoding.
    kem_public_key: MlKem1024EncapsulationKey,
}

impl NoteRecipient {
    /// Checks a typed descriptor and retains an independent immutable recipient snapshot.
    ///
    /// The caller supplies the intended network and remains responsible for address provenance,
    /// prior transport parsing and protocol activation.
    ///
    /// # Errors
    ///
    /// First reports [`NoteRecipientError::NetworkMismatch`] if the complete network differs,
    /// then [`NoteRecipientError::UnsupportedAddressFormat`] for every address version except 1.
    ///
    /// Suite resolution follows without fallback, preserving its original error as
    /// [`NoteRecipientError::UnsupportedSuite`] before key import can report
    /// [`NoteRecipientError::InvalidEncapsulationKey`].
    pub fn validate(
        descriptor: &RecipientDescriptor,
        expected_network: NetworkId,
    ) -> Result<Self, NoteRecipientError> {
        let context = descriptor.context();
        let actual = context.network_id();
        if actual != expected_network {
            return Err(NoteRecipientError::NetworkMismatch { actual });
        }

        validate_address_format(context.format_version())?;

        // Keep later suite additions from silently widening the address format's rules.
        let suite = match CryptoSuite::try_from(context.crypto_suite_id())? {
            CryptoSuite::V1 => CryptoSuite::V1,
        };
        let kem_public_key = MlKem1024EncapsulationKey::try_from(descriptor.kem_public_key())?;

        Ok(Self {
            context,
            suite,
            ownership_commitment: descriptor.ownership_commitment(),
            kem_public_key,
        })
    }

    /// Returns the checked address context without asserting protocol activation.
    pub const fn context(&self) -> AddressContext {
        self.context
    }

    /// Returns the recognized suite allowed by this recipient's address format.
    pub const fn suite(&self) -> CryptoSuite {
        self.suite
    }

    /// Returns the declared ownership commitment without proving its opening.
    pub const fn ownership_commitment(&self) -> OwnershipCommitment {
        self.ownership_commitment
    }

    /// Borrows the complete validated public key retained for recipient binding and encryption.
    pub const fn kem_public_key(&self) -> &MlKem1024EncapsulationKey {
        &self.kem_public_key
    }
}

/// Recognizes the complete address format identifier without narrowing or selecting a fallback.
fn validate_address_format(version: AddressFormatVersion) -> Result<(), NoteRecipientError> {
    if version.value() != 1 {
        return Err(NoteRecipientError::UnsupportedAddressFormat { version });
    }

    Ok(())
}

/// Recipient retention, complete context checks and public key validation precedence.
#[cfg(test)]
mod tests {
    use houseki_crypto::{CryptoSuite, CryptoSuiteError, MlKem1024EncapsulationKeyError};
    use houseki_types::{
        AddressContext, AddressFormatVersion, CryptoSuiteId, EncodedMlKem1024PublicKey, NetworkId,
        OwnershipCommitment, RecipientDescriptor,
    };

    use crate::{NoteRecipient, NoteRecipientError};

    /// Builds a declared context with the supported address format and suite.
    fn context() -> AddressContext {
        AddressContext::new(
            NetworkId::from_bytes([7; 64]),
            AddressFormatVersion::new(1),
            CryptoSuiteId::new(1),
        )
    }

    /// Builds a canonical public key with boundary coefficients and a distinct matrix seed.
    fn key() -> EncodedMlKem1024PublicKey {
        let mut bytes = [0; 1568];
        for pair in bytes[..1536].as_chunks_mut::<3>().0 {
            pair.copy_from_slice(&[0x00, 0x0d, 0xd0]);
        }
        bytes[1536..].copy_from_slice(&std::array::from_fn::<_, 32, _>(|index| index as u8));

        EncodedMlKem1024PublicKey::from_bytes(bytes)
    }

    /// Builds an encoded public key with a coefficient outside the canonical range.
    fn invalid_key() -> EncodedMlKem1024PublicKey {
        let mut bytes = key().into_bytes();
        bytes[..3].copy_from_slice(&[0x01, 0x0d, 0x00]);

        EncodedMlKem1024PublicKey::from_bytes(bytes)
    }

    /// Checks exact public field retention after the original descriptor leaves scope.
    #[test]
    fn validation_retains_an_owned_snapshot_of_complete_public_fields() {
        let context = context();
        let ownership = OwnershipCommitment::from_bytes(std::array::from_fn(|index| index as u8));
        let key = key();
        let recipient = {
            let descriptor = RecipientDescriptor::new(context, ownership, key.clone());
            NoteRecipient::validate(&descriptor, context.network_id()).unwrap()
        };

        assert_eq!(recipient.context(), context);
        assert_eq!(recipient.suite(), CryptoSuite::V1);
        assert_eq!(recipient.suite().id(), context.crypto_suite_id());
        assert_eq!(recipient.ownership_commitment(), ownership);
        assert_eq!(recipient.kem_public_key().to_encoded(), key);
        assert_eq!(recipient.clone(), recipient);
    }

    /// Checks every network byte before unsupported identifiers or a malformed key can fail.
    #[test]
    fn network_mismatches_precede_format_suite_and_key_checks() {
        let expected = context().network_id();

        for index in 0..64 {
            let mut bytes = expected.into_bytes();
            bytes[index] ^= 0x80;
            let actual = NetworkId::from_bytes(bytes);
            let descriptor = RecipientDescriptor::new(
                AddressContext::new(actual, AddressFormatVersion::new(0), CryptoSuiteId::new(0)),
                OwnershipCommitment::from_bytes([0; 64]),
                invalid_key(),
            );

            let result = NoteRecipient::validate(&descriptor, expected);

            assert!(matches!(
                result,
                Err(NoteRecipientError::NetworkMismatch { actual: reported }) if reported == actual
            ));
        }
    }

    /// Checks all unsupported address identifier bits before resolving a suite or public key.
    #[test]
    fn unsupported_address_formats_precede_suite_and_key_checks() {
        let network = context().network_id();

        for value in [0, 2, 257, 65_537, 0x0100_0001, u32::MAX] {
            let version = AddressFormatVersion::new(value);
            let descriptor = RecipientDescriptor::new(
                AddressContext::new(network, version, CryptoSuiteId::new(u32::MAX)),
                OwnershipCommitment::from_bytes([0; 64]),
                invalid_key(),
            );

            let result = NoteRecipient::validate(&descriptor, network);

            assert!(matches!(
                result,
                Err(NoteRecipientError::UnsupportedAddressFormat { version: reported })
                    if reported == version
            ));
        }
    }

    /// Checks complete unsupported suite identifiers before importing a malformed public key.
    #[test]
    fn unsupported_suites_precede_key_checks_without_identifier_narrowing() {
        let context = context();
        let network = context.network_id();

        for value in [0, 2, 257, 65_537, 0x0100_0001, u32::MAX] {
            let id = CryptoSuiteId::new(value);
            let descriptor = RecipientDescriptor::new(
                AddressContext::new(network, context.format_version(), id),
                OwnershipCommitment::from_bytes([0; 64]),
                invalid_key(),
            );

            let result = NoteRecipient::validate(&descriptor, network);

            assert!(matches!(
                result,
                Err(NoteRecipientError::UnsupportedSuite(CryptoSuiteError::Unsupported {
                    id: reported,
                })) if reported == id
            ));
        }
    }

    /// Checks coefficient import failures remain errors rather than unchecked recipient values.
    #[test]
    fn noncanonical_public_keys_preserve_the_crypto_validation_error() {
        let context = context();

        for offset in [0, 1533] {
            for pair in [[0x01, 0x0d, 0x00], [0x00, 0x10, 0xd0]] {
                let mut bytes = key().into_bytes();
                bytes[offset..offset + 3].copy_from_slice(&pair);
                let descriptor = RecipientDescriptor::new(
                    context,
                    OwnershipCommitment::from_bytes([0; 64]),
                    EncodedMlKem1024PublicKey::from_bytes(bytes),
                );

                let result = NoteRecipient::validate(&descriptor, context.network_id());

                assert!(matches!(
                    result,
                    Err(NoteRecipientError::InvalidEncapsulationKey(
                        MlKem1024EncapsulationKeyError::NonCanonicalEncoding
                    ))
                ));
            }
        }
    }

    /// Checks ownership remains declared data and canonical matrix seeds need no extra rules.
    #[test]
    fn declared_ownership_digests_and_unrestricted_matrix_seeds_are_retained() {
        let context = context();

        for fill in [0, 0xff] {
            let ownership = OwnershipCommitment::from_bytes([fill; 64]);
            let mut bytes = key().into_bytes();
            bytes[1536..].fill(fill);
            let key = EncodedMlKem1024PublicKey::from_bytes(bytes);
            let descriptor = RecipientDescriptor::new(context, ownership, key.clone());

            let recipient = NoteRecipient::validate(&descriptor, context.network_id()).unwrap();

            assert_eq!(recipient.ownership_commitment(), ownership);
            assert_eq!(recipient.kem_public_key().to_encoded(), key);
        }
    }
}
