//! Protected ML-KEM-1024 results for Houseki key derivation.

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A protected 32 byte result passed internally from ML-KEM-1024 to Houseki's KDF.
///
/// The type keeps its bytes private, redacts debug output and provides no cloning, equality or
/// serialization.
///
/// Stored bytes are zeroized on drop, although this cannot guarantee erasure of backend,
/// compiler or system copies.
///
/// Because decapsulation can return an implicit rejection secret, holding this result does not
/// establish successful recovery or ciphertext authentication.
pub struct MlKem1024SharedSecret(
    /// Stored KEM result cleared by this type's drop implementation.
    [u8; 32],
);

impl MlKem1024SharedSecret {
    /// Consumes the secret to derive a 32 byte key with HKDF-HMAC-SHA512.
    ///
    /// The suite supplies framed salt and info.
    /// The returned extraction key is explicitly cleared, and the derived key remains in
    /// zeroizing storage.
    /// Backend expansion blocks and HMAC temporaries remain outside this cleanup guarantee.
    pub(crate) fn derive_key(self, salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
        let (prk, hkdf) = hkdf::Hkdf::<sha2::Sha512>::extract(Some(salt), &self.0);
        drop(Zeroizing::new(prk));
        let mut key = Zeroizing::new([0; 32]);
        hkdf.expand(info, &mut *key)
            .expect("32 bytes fit the HKDF-SHA512 limit of 255 * 64 bytes");
        key
    }

    /// Copies a backend result into protected storage and clears its guarded buffer.
    pub(super) fn from_backend(secret: Zeroizing<ml_kem::SharedKey>) -> Self {
        Self((*secret).into())
    }
}

impl fmt::Debug for MlKem1024SharedSecret {
    /// Formats a fixed label that conceals the shared secret.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MlKem1024SharedSecret([REDACTED])")
    }
}

impl Drop for MlKem1024SharedSecret {
    /// Clears the stored shared secret before releasing its storage.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Independent KDF vectors and shared secret redaction.
#[cfg(test)]
pub(crate) mod tests {
    use super::MlKem1024SharedSecret;
    use zeroize::Zeroizing;

    impl MlKem1024SharedSecret {
        /// Constructs synthetic shared material available only in tests.
        pub(crate) fn fixture_secret() -> Self {
            Self::from_backend(Zeroizing::new([0xa5; 32].into()))
        }
    }

    /// Checks HKDF output against independent HMAC-SHA512 vectors.
    #[test]
    fn key_derivation_matches_independent_hmac_sha512_vectors() {
        // Python hmac.digest with SHA-512 computes Extract, then T(1) = HMAC(PRK, info || 1).
        for (salt, info, expected) in [
            (
                vec![],
                vec![],
                "45fb0ef98f2783dcc615d109b91efb5e34d0c57733e711c376052905cec4ed4a",
            ),
            (
                (0..129).collect(),
                (0..255).cycle().take(510).collect(),
                "65cd32a96e536bf3f0c4de7c1a2827d17964e004a72fd5baaaae1c4ff73a10fd",
            ),
        ] {
            let key = MlKem1024SharedSecret::fixture_secret().derive_key(&salt, &info);
            let actual: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(actual, expected);
        }
    }

    /// Compares stored secret bytes with a published test vector.
    pub(crate) fn assert_secret_eq(secret: &MlKem1024SharedSecret, expected: &[u8; 32]) {
        assert_eq!(&secret.0, expected);
    }

    /// Compares two stored secrets inside the test boundary.
    pub(crate) fn assert_secrets_eq(left: &MlKem1024SharedSecret, right: &MlKem1024SharedSecret) {
        assert_eq!(left.0, right.0);
    }

    /// Checks redaction in both shared secret debug formats.
    #[test]
    fn diagnostics_redact_shared_material_in_both_debug_formats() {
        let secret = MlKem1024SharedSecret::from_backend(Zeroizing::new([0xa5; 32].into()));

        assert_eq!(format!("{secret:?}"), "MlKem1024SharedSecret([REDACTED])");
        assert_eq!(format!("{secret:#?}"), "MlKem1024SharedSecret([REDACTED])");
    }
}
