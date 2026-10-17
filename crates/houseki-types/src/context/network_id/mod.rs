//! Network identities derived from genesis commitments.

mod error;

pub use error::NetworkIdError;

/// Identifies a network by its 64 byte SHA3-512 genesis commitment.
///
/// This type stores the complete digest without computing it or verifying its relationship to
/// genesis.
///
/// Every byte pattern is representable, so construction alone does not establish a known or
/// trusted network.
///
/// Genesis consumers must derive the commitment using the agreed canonical encoding and domain.
///
/// Transaction authorization must bind this identifier, and consumers must compare it with the
/// expected network.
///
/// Networks sharing the same committed genesis also share this identifier, which does not
/// distinguish their later forks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkId(
    /// Complete declared genesis digest without an authenticated genesis binding.
    [u8; 64],
);

impl NetworkId {
    /// The byte length of the SHA3-512 genesis commitment.
    pub const BYTE_LENGTH: usize = 64;

    /// Stores a complete genesis commitment without verifying its derivation.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the complete genesis commitment bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Consumes the value and returns its complete genesis commitment bytes.
    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for NetworkId {
    /// Error returned when the supplied slice has an invalid encoded length.
    type Error = NetworkIdError;

    /// Copies a complete genesis commitment from a slice, checking only its length.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkIdError::InvalidByteLength`] if the slice does not contain exactly
    /// [`Self::BYTE_LENGTH`] bytes.
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

/// Construction, conversion and rejection properties of [`NetworkId`].
#[cfg(test)]
mod tests {
    use super::{NetworkId, NetworkIdError};

    /// Checks that slice conversion preserves the complete digest in order.
    #[test]
    fn slice_conversion_preserves_the_complete_digest_in_order() {
        let bytes = std::array::from_fn::<_, 64, _>(|index| index as u8);
        let network = NetworkId::try_from(bytes.as_slice()).unwrap();

        assert_eq!(NetworkId::BYTE_LENGTH, 64);
        assert_eq!(network.as_bytes(), &bytes);
        assert_eq!(network.into_bytes(), bytes);
    }

    /// Checks that slice conversion rejects other digest lengths and trailing bytes.
    #[test]
    fn slice_conversion_rejects_other_digest_lengths_and_trailing_bytes() {
        for length in [0, 1, 32, 63, 65, 128] {
            let bytes = vec![0; length];

            assert!(matches!(
                NetworkId::try_from(bytes.as_slice()),
                Err(NetworkIdError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }

    /// Checks that construction preserves unverified digest bytes.
    #[test]
    fn construction_preserves_unverified_digest_bytes() {
        for bytes in [[0; 64], [u8::MAX; 64]] {
            let network = NetworkId::from_bytes(bytes);
            let decoded = NetworkId::try_from(bytes.as_slice()).unwrap();

            assert_eq!(network, decoded);
            assert_eq!(network.into_bytes(), bytes);
        }
    }
}
