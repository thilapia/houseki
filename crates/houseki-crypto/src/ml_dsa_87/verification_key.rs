//! Exact public key representation for the fixed ML-DSA-87 parameter set.

use houseki_types::EncodedMlDsa87PublicKey;
use ml_dsa::{MlDsa87, VerifyingKey};

/// An operational ML-DSA-87 public verification key with immutable backend storage.
///
/// Every exact 2592 byte encoding has representable fixed bit fields under FIPS 204.
///
/// Decoding preserves these bytes without establishing honest generation, key possession,
/// account binding, registration or withdrawal authority.
#[derive(Clone, Debug, PartialEq)]
pub struct MlDsa87VerificationKey(
    /// Decoded backend public key and its precomputed public verification data.
    pub(super) VerifyingKey<MlDsa87>,
);

impl MlDsa87VerificationKey {
    /// Decodes the complete public representation without rejecting representable field values.
    pub fn from_encoded(encoded: &EncodedMlDsa87PublicKey) -> Self {
        let bytes = ml_dsa::EncodedVerifyingKey::<MlDsa87>::from(*encoded.as_bytes());

        Self(VerifyingKey::decode(&bytes))
    }

    /// Returns the exact complete public encoding without changing the retained key.
    pub fn to_encoded(&self) -> EncodedMlDsa87PublicKey {
        EncodedMlDsa87PublicKey::from_bytes(self.0.encode().into())
    }
}

/// Lossless decoding for every fixed public field rather than an invented key validity rule.
#[cfg(test)]
mod tests {
    use crate::MlDsa87VerificationKey;
    use houseki_types::EncodedMlDsa87PublicKey;

    /// Preserves all byte patterns, including the complete unrestricted seed and packed coefficients.
    #[test]
    fn public_keys_preserve_exact_encodings() {
        for bytes in [
            [0; 2592],
            [0xff; 2592],
            std::array::from_fn(|i| u8::try_from(i % 256).unwrap()),
        ] {
            let encoded = EncodedMlDsa87PublicKey::from_bytes(bytes);
            let key = MlDsa87VerificationKey::from_encoded(&encoded);

            assert_eq!(key.to_encoded(), encoded);
            assert_eq!(key.clone().to_encoded(), encoded);
        }
    }
}
