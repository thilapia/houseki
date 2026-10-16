//! Protected ML-KEM-1024 results for Houseki key derivation.

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A protected 32 byte result of an ML-KEM-1024 operation.
///
/// Only the KEM implementation can construct this value. Its bytes remain
/// internal to Houseki for use by the encryption suite's key derivation.
/// This value is not an AEAD key and does not establish successful recovery,
/// recipient identity or ciphertext authentication.
///
/// Debug output is redacted. The type has no public byte access, cloning,
/// equality or serialization. Its stored bytes are zeroized on drop, without
/// guaranteeing erasure of backend intermediates, compiler or system copies.
pub struct MlKem1024SharedSecret([u8; 32]);

impl MlKem1024SharedSecret {
    /// Consumes this secret to derive the suite's fixed 32-byte operation key.
    ///
    /// Only the suite supplies framed salt and info. No raw-secret accessor is
    /// needed. Guard the returned PRK explicitly: the backend's convenience
    /// constructor discards that buffer without zeroizing it. Backend expansion
    /// blocks and HMAC temporaries are outside this stored-buffer guarantee.
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MlKem1024SharedSecret([REDACTED])")
    }
}

impl Drop for MlKem1024SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::MlKem1024SharedSecret;
    use zeroize::Zeroizing;

    impl MlKem1024SharedSecret {
        pub(crate) fn fixture_secret() -> Self {
            Self::from_backend(Zeroizing::new([0xa5; 32].into()))
        }
    }

    #[test]
    fn key_derivation_matches_independent_hmac_sha512_vectors() {
        // Python hmac.digest with SHA-512: Extract, then T(1) = HMAC(PRK, info || 1).
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

    pub(crate) fn assert_secret_eq(secret: &MlKem1024SharedSecret, expected: &[u8; 32]) {
        assert_eq!(&secret.0, expected);
    }

    pub(crate) fn assert_secrets_eq(left: &MlKem1024SharedSecret, right: &MlKem1024SharedSecret) {
        assert_eq!(left.0, right.0);
    }

    #[test]
    fn diagnostics_redact_shared_material_in_both_debug_formats() {
        let secret = MlKem1024SharedSecret::from_backend(Zeroizing::new([0xa5; 32].into()));

        assert_eq!(format!("{secret:?}"), "MlKem1024SharedSecret([REDACTED])");
        assert_eq!(format!("{secret:#?}"), "MlKem1024SharedSecret([REDACTED])");
    }
}
