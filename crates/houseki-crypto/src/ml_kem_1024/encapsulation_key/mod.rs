//! Validated public encapsulation keys for ML-KEM-1024.

mod error;

pub use error::MlKem1024EncapsulationKeyError;

use houseki_types::EncodedMlKem1024PublicKey;
use ml_kem::{KeyExport, ml_kem_1024::EncapsulationKey};

/// An ML-KEM-1024 public encapsulation key with a validated encoding.
///
/// Import checks the polynomial coefficients according to FIPS 203 Section 7.2.
///
/// The encoded input type already guarantees the required 1568 byte length.
///
/// Validation does not establish honest key generation, recipient identity or
/// possession of the corresponding private key.
///
/// The backend representation is private and cannot be modified after import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKem1024EncapsulationKey(EncapsulationKey);

impl MlKem1024EncapsulationKey {
    /// Returns the complete public encoding without changing its bytes.
    pub fn to_encoded(&self) -> EncodedMlKem1024PublicKey {
        EncodedMlKem1024PublicKey::from_bytes(self.0.to_bytes().into())
    }
}

impl TryFrom<&EncodedMlKem1024PublicKey> for MlKem1024EncapsulationKey {
    type Error = MlKem1024EncapsulationKeyError;

    /// Imports a public key after checking its coefficient encoding.
    ///
    /// # Errors
    ///
    /// Returns [`MlKem1024EncapsulationKeyError::NonCanonicalEncoding`] if any
    /// encoded polynomial coefficient is outside the range from 0 through 3328.
    ///
    /// The final 32 bytes contain the public matrix seed and are unrestricted.
    fn try_from(encoded: &EncodedMlKem1024PublicKey) -> Result<Self, Self::Error> {
        EncapsulationKey::new(encoded.as_bytes().into())
            .map(Self)
            .map_err(|_| Self::Error::NonCanonicalEncoding)
    }
}

#[cfg(test)]
mod tests {
    use houseki_types::EncodedMlKem1024PublicKey;

    use crate::{MlKem1024EncapsulationKey, MlKem1024EncapsulationKeyError};

    #[test]
    fn accepts_zero_coefficients_and_unrestricted_seed_bytes() {
        for seed_byte in [0, 0xff] {
            let mut bytes = [0; 1568];
            bytes[1536..].fill(seed_byte);
            let encoded = EncodedMlKem1024PublicKey::from_bytes(bytes);

            let key = MlKem1024EncapsulationKey::try_from(&encoded).unwrap();

            assert_eq!(key.to_encoded(), encoded);
        }
    }

    #[test]
    fn accepts_boundary_coefficients_and_preserves_the_complete_encoding() {
        let mut bytes = [0; 1568];
        // Each three-byte group encodes two little-endian 12-bit coefficients.
        // These literal fixtures follow FIPS 203 ByteEncode_12 with q = 3329.
        for pair in bytes[..1536].as_chunks_mut::<3>().0 {
            pair.copy_from_slice(&[0x00, 0x0d, 0xd0]); // (3328, 3328)
        }
        bytes[..3].copy_from_slice(&[0x00, 0x00, 0xd0]); // (0, 3328)
        bytes[3..6].copy_from_slice(&[0x00, 0x0d, 0x00]); // (3328, 0)
        bytes[1533..1536].copy_from_slice(&[0x01, 0xf0, 0xcf]); // (1, 3327)
        bytes[1536..].copy_from_slice(&std::array::from_fn::<_, 32, _>(|i| i as u8));
        let encoded = EncodedMlKem1024PublicKey::from_bytes(bytes);

        let key = MlKem1024EncapsulationKey::try_from(&encoded).unwrap();

        assert_eq!(key.to_encoded(), encoded);
    }

    #[test]
    fn rejects_noncanonical_coefficients_in_both_packing_positions_and_every_polynomial() {
        let invalid_pairs = [
            [0x01, 0x0d, 0x00], // (3329, 0)
            [0x00, 0x10, 0xd0], // (0, 3329)
            [0xff, 0x0f, 0x00], // (4095, 0)
            [0x00, 0xf0, 0xff], // (0, 4095)
        ];

        for offset in [0, 381, 384, 765, 768, 1149, 1152, 1533] {
            for pair in invalid_pairs {
                let mut bytes = [0; 1568];
                bytes[offset..offset + 3].copy_from_slice(&pair);
                let encoded = EncodedMlKem1024PublicKey::from_bytes(bytes);

                assert!(
                    matches!(
                        MlKem1024EncapsulationKey::try_from(&encoded),
                        Err(MlKem1024EncapsulationKeyError::NonCanonicalEncoding)
                    ),
                    "accepted invalid coefficient pair {pair:?} at byte offset {offset}"
                );
            }
        }
    }
}
