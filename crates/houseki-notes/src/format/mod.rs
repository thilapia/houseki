//! Recognition of supported immutable note rules.

mod error;

pub use error::NoteFormatError;

use houseki_types::NoteVersion;

/// A recognized immutable set of note opening, commitment and nullifier rules.
///
/// [`Self::try_from`] resolves the complete note version without fallback, independently of
/// transaction protocol versions, address formats and encryption suite identifiers.
///
/// Recognizing a format identifies the rules that consumers must enforce, without checking
/// protocol activation or validating an opening, commitment, recipient or spending authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoteFormat {
    /// The first immutable note format, assigned note version 1.
    ///
    /// Ordinary notes contain a positive amount through [`houseki_types::Amount::MAX_ATOMS`]
    /// and fresh 32 byte blinding, with the same rules for recipients and change.
    ///
    /// Private plaintext occupies exactly 52 bytes, containing a four byte little endian
    /// version, a sixteen byte little endian atom count and the complete blinding, without
    /// padding, optional fields or trailing bytes.
    ///
    /// Delivery uses [`houseki_crypto::CryptoSuite::V1`], with network and recipient information
    /// supplied by the checked body context and validated recipient snapshot.
    ///
    /// The fixed commitment and nullifier relations bind that network and immutable version,
    /// with commitment binding ownership, internally derived recipient key binding, amount
    /// and blinding, and nullifier binding the secret nullifier key, commitment and original
    /// insertion position.
    ///
    /// Opening consumers must enforce these rules and match the recomputed commitment to the
    /// selected output, while encoding, derivation and recovery have separate interfaces.
    V1,
}

impl NoteFormat {
    /// Returns the note version assigned to these immutable rules.
    pub const fn version(&self) -> NoteVersion {
        match self {
            Self::V1 => NoteVersion::new(1),
        }
    }
}

impl TryFrom<NoteVersion> for NoteFormat {
    /// Error returned when a version has no supported immutable note rules.
    type Error = NoteFormatError;

    /// Resolves a complete note version without selecting a fallback format.
    ///
    /// # Errors
    ///
    /// Returns [`NoteFormatError::Unsupported`] for every version other than 1, retaining all
    /// identifier bits without establishing activation or note validity.
    fn try_from(version: NoteVersion) -> Result<Self, Self::Error> {
        match version.value() {
            1 => Ok(Self::V1),
            _ => Err(NoteFormatError::Unsupported { version }),
        }
    }
}

/// Exact format recognition and preservation of unsupported version identifiers.
#[cfg(test)]
mod tests {
    use crate::{NoteFormat, NoteFormatError};
    use houseki_types::NoteVersion;

    /// Checks the assigned format resolves and exposes its version in constant contexts.
    #[test]
    fn note_version_one_resolves_to_the_fixed_v1_rules() {
        /// Version selected by the initial immutable note rules.
        const VERSION: NoteVersion = NoteFormat::V1.version();

        let format = NoteFormat::try_from(NoteVersion::new(1)).unwrap();

        assert_eq!(format, NoteFormat::V1);
        assert_eq!(format.version(), NoteVersion::new(1));
        assert_eq!(VERSION, NoteVersion::new(1));
    }

    /// Checks unsupported identifiers are retained even when they share V1's low byte.
    #[test]
    fn unsupported_note_versions_preserve_all_identifier_bits() {
        for value in [0, 2, 257, 65_537, 0x0100_0001, u32::MAX] {
            let version = NoteVersion::new(value);

            let result = NoteFormat::try_from(version);

            assert!(matches!(
                result,
                Err(NoteFormatError::Unsupported { version: reported }) if reported == version
            ));
        }
    }
}
