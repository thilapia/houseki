//! Failures while generating fresh spending key material.

use thiserror::Error;

/// A failure to obtain a complete spending key from the system random source.
#[derive(Debug, Error)]
pub enum SpendingKeyError {
    /// The entropy source could not supply all required bytes, even after a partial write.
    #[error("could not obtain randomness for spending key generation")]
    RandomnessUnavailable,
}
