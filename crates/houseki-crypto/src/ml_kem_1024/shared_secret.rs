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

    pub(crate) fn assert_secret_eq(secret: &MlKem1024SharedSecret, expected: &[u8; 32]) {
        assert_eq!(&secret.0, expected);
    }

    #[test]
    fn diagnostics_redact_shared_material_in_both_debug_formats() {
        let secret = MlKem1024SharedSecret::from_backend(Zeroizing::new([0xa5; 32].into()));

        assert_eq!(format!("{secret:?}"), "MlKem1024SharedSecret([REDACTED])");
        assert_eq!(format!("{secret:#?}"), "MlKem1024SharedSecret([REDACTED])");
    }
}
