//! Failures to acquire complete ML-DSA-87 signing key randomness.

use thiserror::Error;

/// A failure to acquire a complete private ML-DSA-87 seed.
#[derive(Debug, Error)]
pub enum MlDsa87SigningKeyError {
    /// System entropy could not supply the complete 32 byte seed.
    #[error("ML-DSA-87 signing key randomness is unavailable")]
    RandomnessUnavailable,
}
