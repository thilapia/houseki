//! Canonical proof representation and allocation failures.

/// Failures detected without interpreting a malformed object as a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CodecError {
    /// The complete encoded proof exceeds its inclusive byte cap.
    #[error("proof exceeds byte limit")]
    ProofTooLarge,

    /// Required canonical bytes are missing.
    #[error("truncated proof")]
    Truncated,

    /// The complete wire version is unsupported.
    #[error("unsupported proof version")]
    UnsupportedVersion,

    /// A header disagrees with the independently selected identity.
    #[error("proof identity mismatch")]
    IdentityMismatch,

    /// The declared payload length disagrees with the actual remaining bytes.
    #[error("proof length mismatch")]
    LengthMismatch,

    /// A base field word is not its unique canonical representative.
    #[error("noncanonical field element")]
    NonCanonicalField,

    /// Proof dimensions disagree with the trusted layout or a fixed backend rule.
    #[error("invalid proof shape")]
    InvalidShape,

    /// Bytes remain after the exact expected payload.
    #[error("trailing proof bytes")]
    TrailingBytes,

    /// Checked vector storage would exceed the decoder's allocation budget.
    #[error("decoded proof exceeds allocation limit")]
    AllocationLimit,

    /// The allocator could not reserve already bounded public proof storage.
    #[error("proof allocation failed")]
    AllocationFailed,
}
