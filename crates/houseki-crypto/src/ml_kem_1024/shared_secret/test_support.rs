//! Shared protected KEM fixtures and comparisons for sibling component tests.

use super::MlKem1024SharedSecret;
use zeroize::Zeroizing;

/// Compares stored secret bytes with a published test vector.
pub(in crate::ml_kem_1024) fn assert_secret_eq(
    secret: &MlKem1024SharedSecret,
    expected: &[u8; 32],
) {
    assert_eq!(&secret.0, expected);
}

/// Compares two stored secrets inside the test boundary.
pub(in crate::ml_kem_1024) fn assert_secrets_eq(
    left: &MlKem1024SharedSecret,
    right: &MlKem1024SharedSecret,
) {
    assert_eq!(left.0, right.0);
}

impl MlKem1024SharedSecret {
    /// Constructs synthetic shared material available only in tests.
    pub(crate) fn fixture_secret() -> Self {
        Self::from_backend(Zeroizing::new([0xa5; 32].into()))
    }
}
