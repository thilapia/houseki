//! Public transaction proof failures with bounded diagnostics and no backend or witness values.

#[cfg(feature = "prover")]
use crate::backend::BackendError;
use crate::{StatementError, backend::CodecError};
use houseki_types::BodyCodecError;

/// Canonical proof representation failures before cryptographic verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofEncodingError {
    /// Required proof bytes are absent.
    #[error("truncated proof")]
    Truncated,

    /// The envelope names an unsupported encoding version.
    #[error("unsupported proof version")]
    UnsupportedVersion,

    /// The header differs from the independently resolved relation identity.
    #[error("proof identity mismatch")]
    IdentityMismatch,

    /// Declared payload length differs from the supplied bytes.
    #[error("proof length mismatch")]
    LengthMismatch,

    /// A field word is not its unique canonical representative.
    #[error("noncanonical field element")]
    NonCanonicalField,

    /// Dimensions or requested storage violate the selected profile.
    #[error("invalid proof shape")]
    InvalidShape,

    /// Bytes remain after the complete expected payload.
    #[error("trailing proof bytes")]
    TrailingBytes,
}

/// Failure to verify the complete relation against the caller's actual body and context.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Another operation owns this runtime's single slot.
    #[error("proof runtime is busy")]
    Busy,

    /// The public body is incompatible with the expected statement.
    #[error(transparent)]
    Statement(
        /// Original bounded public statement failure.
        StatementError,
    ),

    /// Complete proof bytes exceed the inclusive profile limit.
    #[error("proof exceeds byte limit")]
    ProofTooLarge,

    /// Proof bytes violate the fixed canonical representation.
    #[error(transparent)]
    Encoding(
        /// Canonical public encoding failure.
        ProofEncodingError,
    ),

    /// Bounded public storage could not be reserved.
    #[error("proof allocation failed")]
    AllocationFailed,

    /// Cryptographic verification rejected the expected relation.
    #[error("invalid proof")]
    InvalidProof,

    /// The compiled backend cannot perform the requested operation.
    #[error("proof backend is unavailable")]
    BackendUnavailable,
}

impl From<StatementError> for VerifyError {
    /// Normalizes public allocation failures without losing other statement diagnostics.
    fn from(error: StatementError) -> Self {
        match error {
            StatementError::InvalidBody(BodyCodecError::AllocationFailed) => Self::AllocationFailed,
            error => Self::Statement(error),
        }
    }
}

impl From<CodecError> for VerifyError {
    /// Separates byte and allocation limits from malformed public encoding.
    fn from(error: CodecError) -> Self {
        let encoding = match error {
            CodecError::ProofTooLarge => return Self::ProofTooLarge,
            CodecError::AllocationFailed => return Self::AllocationFailed,
            CodecError::Truncated => ProofEncodingError::Truncated,
            CodecError::UnsupportedVersion => ProofEncodingError::UnsupportedVersion,
            CodecError::IdentityMismatch => ProofEncodingError::IdentityMismatch,
            CodecError::LengthMismatch => ProofEncodingError::LengthMismatch,
            CodecError::NonCanonicalField => ProofEncodingError::NonCanonicalField,
            CodecError::InvalidShape | CodecError::AllocationLimit => {
                ProofEncodingError::InvalidShape
            }
            CodecError::TrailingBytes => ProofEncodingError::TrailingBytes,
        };

        Self::Encoding(encoding)
    }
}

impl From<crate::backend::VerificationError> for VerifyError {
    /// Keeps canonical decoding failures distinct from an invalid cryptographic proof.
    fn from(error: crate::backend::VerificationError) -> Self {
        match error {
            crate::backend::VerificationError::Encoding(error) => error.into(),
            crate::backend::VerificationError::InvalidProof => Self::InvalidProof,
        }
    }
}

/// Failure to prepare or prove an opening without revealing any private input or backend string.
#[cfg(feature = "prover")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProveError {
    /// Another operation owns this runtime's single slot.
    #[error("proof runtime is busy")]
    Busy,

    /// Cancellation was requested or this attempt's token was already used.
    #[error("proof attempt cancelled")]
    Cancelled,

    /// The public body is incompatible with the expected statement.
    #[error(transparent)]
    Statement(
        /// Original bounded public statement failure.
        StatementError,
    ),

    /// Actual witness counts differ from the body shape.
    #[error("witness counts do not match the body")]
    WitnessCountMismatch,

    /// A private opening fails the selected native relation or trace rules.
    #[error("invalid witness")]
    InvalidWitness,

    /// The operating system could not supply complete fresh private seeds.
    #[error("proof entropy unavailable")]
    EntropyUnavailable,

    /// Bounded proof storage could not be reserved.
    #[error("proof allocation failed")]
    AllocationFailed,

    /// Complete encoded proof bytes exceed the inclusive profile limit.
    #[error("proof exceeds byte limit")]
    ProofTooLarge,

    /// Protected proving failed without returning a complete proof.
    #[error("proof backend failed")]
    BackendFailure,

    /// Required allocator protection or backend execution mode is unavailable.
    #[error("protected prover backend is unavailable")]
    BackendUnavailable,
}

#[cfg(feature = "prover")]
impl From<StatementError> for ProveError {
    /// Normalizes public allocation failure before any private witness is imported.
    fn from(error: StatementError) -> Self {
        match error {
            StatementError::InvalidBody(BodyCodecError::AllocationFailed) => Self::AllocationFailed,
            error => Self::Statement(error),
        }
    }
}

#[cfg(feature = "prover")]
impl From<BackendError> for ProveError {
    /// Maps private execution failures to fixed public categories without backend diagnostics.
    fn from(error: BackendError) -> Self {
        match error {
            BackendError::EntropyUnavailable => Self::EntropyUnavailable,
            BackendError::AllocationFailed => Self::AllocationFailed,
            BackendError::Cancelled => Self::Cancelled,
            BackendError::BackendUnavailable => Self::BackendUnavailable,
            BackendError::InvalidTrace => Self::InvalidWitness,
            BackendError::ProofTooLarge => Self::ProofTooLarge,
            BackendError::ProvingFailed | BackendError::InvalidProof => Self::BackendFailure,
        }
    }
}

/// Public consumers can distinguish malformed encodings from storage and size failures.
#[cfg(test)]
mod tests {
    use super::*;

    /// Header, field, shape and limit errors survive the facade without backend type exposure.
    #[test]
    fn reward_withdrawal_errors_preserve_public_failure_categories() {
        assert!(matches!(
            VerifyError::from(CodecError::ProofTooLarge),
            VerifyError::ProofTooLarge
        ));
        assert!(matches!(
            VerifyError::from(CodecError::AllocationFailed),
            VerifyError::AllocationFailed
        ));
        assert!(matches!(
            VerifyError::from(CodecError::IdentityMismatch),
            VerifyError::Encoding(ProofEncodingError::IdentityMismatch)
        ));
        assert!(matches!(
            VerifyError::from(CodecError::AllocationLimit),
            VerifyError::Encoding(ProofEncodingError::InvalidShape)
        ));
        assert!(matches!(
            VerifyError::from(StatementError::InvalidBody(
                BodyCodecError::AllocationFailed
            )),
            VerifyError::AllocationFailed
        ));
    }
}
