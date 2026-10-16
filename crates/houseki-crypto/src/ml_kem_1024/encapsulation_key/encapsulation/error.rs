use thiserror::Error;

/// A failure to encapsulate a new ML-KEM-1024 shared secret.
#[derive(Debug, Error)]
pub enum MlKem1024EncapsulationError {
    /// The system random source could not supply all required secret randomness.
    #[error("could not obtain randomness for ML-KEM-1024 encapsulation")]
    RandomnessUnavailable,
}
