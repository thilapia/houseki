//! Redacted failures from private proof preparation and execution.

use super::codec::CodecError;

/// Redacted failures from private backend preparation or execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendError {
    /// The operating system could not supply every required private seed.
    EntropyUnavailable,

    /// A bounded storage request could not be allocated.
    AllocationFailed,

    /// Cancellation discarded this attempt or its token had already been consumed.
    Cancelled,

    /// Private allocation protection or complete release accounting was unavailable.
    BackendUnavailable,

    /// Trace dimensions do not match the selected AIR or hiding floor.
    InvalidTrace,

    /// The pinned prover failed without returning a complete proof.
    ProvingFailed,

    /// Canonical proof encoding exceeds the complete output byte limit.
    ProofTooLarge,

    /// Cryptographic verification or expected public dimensions failed.
    InvalidProof,
}

impl From<CodecError> for BackendError {
    /// Preserves actionable output limits without exposing private backend proof details.
    fn from(error: CodecError) -> Self {
        match error {
            CodecError::ProofTooLarge => Self::ProofTooLarge,
            CodecError::AllocationFailed => Self::AllocationFailed,
            _ => Self::ProvingFailed,
        }
    }
}

/// Public proof decoding and cryptographic failures without exposing a decoded backend object.
pub(crate) enum VerificationError {
    /// Canonical bytes violate the trusted profile or resource bounds.
    Encoding(
        /// Original bounded public encoding failure.
        CodecError,
    ),

    /// The complete relation did not verify against the independently reconstructed statement.
    InvalidProof,
}
