//! Failures while generating fresh nullifier key material.

use thiserror::Error;

/// A failure to obtain a complete nullifier key from the system random source.
#[derive(Debug, Error)]
pub enum NullifierKeyError {
    /// The entropy source could not supply all required bytes, even after a partial write.
    #[error("could not obtain randomness for nullifier key generation")]
    RandomnessUnavailable,
}
