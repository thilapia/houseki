//! Canonical complete address text shared by copying, files and QR transport.

mod error;

pub use error::NoteAddressError;

use super::NoteRecipient;
use base64ct::{Base64UrlUnpadded, Encoding};
use houseki_crypto::{CryptoFramingError, recipient_descriptor_checksum};
use houseki_types::NetworkId;

impl NoteRecipient {
    /// Encodes this complete recipient as canonical address text with its transcription checksum.
    ///
    /// Files and QR transports carry this exact full ASCII string without newline or terminator.
    ///
    /// The checksum does not authenticate provenance or the intended recipient.
    ///
    /// # Errors
    ///
    /// Preserves any checksum framing failure without returning a partial string.
    pub fn to_address(&self) -> Result<String, CryptoFramingError> {
        let bytes = self.to_bytes();
        let checksum = recipient_descriptor_checksum(&bytes)?;

        let mut text = String::with_capacity(2298);
        text.push_str("houseki1:");
        text.push_str(&Base64UrlUnpadded::encode_string(&bytes));
        text.push(':');
        for byte in checksum {
            text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            text.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
        }

        Ok(text)
    }

    /// Parses exact canonical address text and validates it against the expected network.
    ///
    /// No whitespace, padding, case folding, Unicode normalization or recipient lookup is used.
    ///
    /// # Errors
    ///
    /// Checks byte length, prefix, alphabet and lowercase checksum syntax before checksum equality,
    /// then delegates complete descriptor network, version, suite and canonical key checks.
    pub fn from_address(text: &str, expected_network: NetworkId) -> Result<Self, NoteAddressError> {
        if text.len() != 2298
            || !text.is_ascii()
            || !text.starts_with("houseki1:")
            || text.as_bytes()[2281] != b':'
        {
            return Err(NoteAddressError::InvalidText);
        }

        let mut bytes = [0; 1704];
        Base64UrlUnpadded::decode(&text[9..2281], &mut bytes)
            .map_err(|_| NoteAddressError::InvalidText)?;

        if !text.as_bytes()[2282..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(NoteAddressError::InvalidText);
        }

        let mut checksum = [0; 8];
        for (index, byte) in checksum.iter_mut().enumerate() {
            let start = 2282 + index * 2;
            *byte = u8::from_str_radix(&text[start..start + 2], 16)
                .map_err(|_| NoteAddressError::InvalidText)?;
        }

        if checksum != recipient_descriptor_checksum(&bytes)? {
            return Err(NoteAddressError::ChecksumMismatch);
        }

        Ok(Self::from_bytes(&bytes, expected_network)?)
    }
}

/// Independent address vectors, strict syntax and descriptor validation precedence.
#[cfg(test)]
mod tests {
    use crate::{NoteAddressError, NoteRecipient, NoteRecipientError};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use houseki_crypto::recipient_descriptor_checksum;
    use houseki_types::NetworkId;

    /// Builds the independent canonical descriptor with zero coefficients and full network bytes.
    fn descriptor() -> [u8; 1704] {
        let mut bytes = [0; 1704];
        bytes[0] = 1;
        bytes[4..68].fill(7);
        bytes[68] = 1;

        bytes
    }

    /// Creates checksummed transport bytes for intentionally invalid descriptors in precedence tests.
    fn transport(bytes: &[u8; 1704]) -> String {
        let checksum = recipient_descriptor_checksum(bytes).unwrap();
        let checksum: String = checksum.iter().map(|b| format!("{b:02x}")).collect();

        format!(
            "houseki1:{}:{checksum}",
            Base64UrlUnpadded::encode_string(bytes)
        )
    }

    /// Compares the exact full address with Python base64url and hashlib independent framing.
    #[test]
    fn address_text_matches_the_complete_independent_v1_vector() {
        let expected = concat!(
            "houseki1:AQAAAAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcBAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:166573380c2f1571"
        );
        let recipient =
            NoteRecipient::from_bytes(&descriptor(), NetworkId::from_bytes([7; 64])).unwrap();

        assert_eq!(recipient.to_address().unwrap(), expected);
        assert_eq!(expected.len(), 2298);
        assert_eq!(
            NoteRecipient::from_address(expected, NetworkId::from_bytes([7; 64])).unwrap(),
            recipient
        );
        assert_eq!(recipient.to_bytes(), descriptor());
    }

    /// Detects a change at every full address byte without accepting a truncated or amended transport.
    #[test]
    fn address_text_rejects_every_single_character_mutation_and_noncanonical_syntax() {
        let text = transport(&descriptor());
        let network = NetworkId::from_bytes([7; 64]);

        for index in 0..text.len() {
            let mut bytes = text.as_bytes().to_vec();
            bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };

            let changed = String::from_utf8(bytes).unwrap();

            assert!(
                NoteRecipient::from_address(&changed, network).is_err(),
                "byte {index}"
            );
        }

        for changed in [
            String::new(),
            text[..2297].to_string(),
            format!("{text}\n"),
            format!(" {text}"),
            format!("{text}="),
            text.replacen("houseki", "HOUSEKI", 1),
        ] {
            assert!(matches!(
                NoteRecipient::from_address(&changed, network),
                Err(NoteAddressError::InvalidText)
            ));
        }

        let mut unicode = text.clone();
        unicode.replace_range(9..11, "é");

        assert_eq!(unicode.len(), 2298);
        assert!(matches!(
            NoteRecipient::from_address(&unicode, network),
            Err(NoteAddressError::InvalidText)
        ));
    }

    /// Checks checksum before network and complete descriptor rules without bypassing full identifiers.
    #[test]
    fn address_text_validates_checksum_then_the_complete_recipient() {
        let network = NetworkId::from_bytes([7; 64]);
        let bytes = descriptor();
        let text = transport(&bytes);

        assert!(matches!(
            NoteRecipient::from_address(&text, NetworkId::from_bytes([6; 64])),
            Err(NoteAddressError::Recipient(
                NoteRecipientError::NetworkMismatch { .. }
            ))
        ));

        for version in [0_u32, 2, 257, 0x0100_0001, u32::MAX] {
            let mut bytes = descriptor();
            bytes[..4].copy_from_slice(&version.to_le_bytes());
            let mut text = transport(&bytes);

            assert!(matches!(
                NoteRecipient::from_address(&text, network),
                Err(NoteAddressError::Recipient(
                    NoteRecipientError::UnsupportedAddressFormat { .. }
                ))
            ));

            text.replace_range(2297..2298, if &text[2297..] == "0" { "1" } else { "0" });

            assert!(matches!(
                NoteRecipient::from_address(&text, network),
                Err(NoteAddressError::ChecksumMismatch)
            ));
        }

        let mut bytes = descriptor();
        bytes[136..139].copy_from_slice(&[0xff, 0x0f, 0]);

        assert!(matches!(
            NoteRecipient::from_address(&transport(&bytes), network),
            Err(NoteAddressError::Recipient(
                NoteRecipientError::InvalidEncapsulationKey(_)
            ))
        ));
    }
}
