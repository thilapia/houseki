//! Errors from public key encoding validation.

use thiserror::Error;

/// A failure to validate an encoded ML-KEM-1024 public encapsulation key.
#[derive(Debug, Error)]
pub enum MlKem1024EncapsulationKeyError {
    /// At least one encoded polynomial coefficient is outside the canonical range.
    #[error("encoded ML-KEM-1024 public key contains a coefficient outside 0 through 3328")]
    NonCanonicalEncoding,
}
