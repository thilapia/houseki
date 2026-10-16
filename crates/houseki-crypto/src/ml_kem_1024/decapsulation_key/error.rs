//! Errors from private key generation.

use thiserror::Error;

/// A failure to generate an ML-KEM-1024 private decapsulation key.
#[derive(Debug, Error)]
pub enum MlKem1024DecapsulationKeyError {
    /// The system random source could not supply the complete secret seed.
    #[error("could not obtain randomness for an ML-KEM-1024 private key")]
    RandomnessUnavailable,
}
