//! Whole unit input, operational and integrity failures never represented as state
//! receipts.

/// Failure before a complete immutable unit can become authorized.
#[derive(Debug, thiserror::Error)]
pub enum UnitPreparationError {
    /// Source identity/author or actual component bytes violate the selected parent
    /// bounds.
    #[error("unit source binding or component bound mismatch")]
    InputBound,

    /// No independently authenticated network/count descriptor exists for the payment
    /// root.
    #[error("unresolved trusted payment anchor")]
    UnresolvedAnchor,

    /// Trusted metadata or supposedly fixed verification dependencies conflict.
    #[error("inconsistent verification dependencies")]
    Integrity,

    /// The closed account registry has no entry for the declared withdrawal source.
    #[error("unknown withdrawal source account")]
    UnknownAccount,

    /// Declared account identity or complete authority differs from its immutable
    /// registration.
    #[error("withdrawal authority binding mismatch")]
    Authority,

    /// The understood profile belongs to another relation.
    #[error("profile relation mismatch")]
    Relation,

    /// Compiled registry recognition failed independently of proof bytes.
    #[error(transparent)]
    Context(
        /// Original context failure retained as the source.
        #[from]
        houseki_proofs::ContextError,
    ),

    /// Actual body representation violates independently recognized limits.
    #[error(transparent)]
    Body(
        /// Original body failure retained as the source.
        #[from]
        houseki_types::BodyCodecError,
    ),

    /// Immutable compatibility bytes could not be encoded.
    #[error(transparent)]
    Artifact(
        /// Original artifact failure retained as the source.
        #[from]
        crate::ArtifactError,
    ),

    /// A bounded local dependency collection could not be reserved.
    #[error("unit dependency allocation failed")]
    Allocation,

    /// Public authority hashing failed locally.
    #[error(transparent)]
    Hash(
        /// Original hash failure retained as the source.
        #[from]
        houseki_crypto::CryptoFramingError,
    ),

    /// Required native source signature failed independently of its output proof.
    #[error(transparent)]
    Signature(
        /// Original signature failure retained as the source.
        #[from]
        houseki_crypto::WithdrawalSignatureError,
    ),

    /// Complete cryptographic input failed verification.
    #[error("invalid unit cryptographic input: {0}")]
    InvalidProof(
        /// Original failure from native cryptographic verification.
        houseki_proofs::VerifyError,
    ),

    /// Local runtime admission, memory or backend availability prevented verification.
    #[error("unit verification unavailable: {0}")]
    Operational(
        /// Original local runtime or backend failure.
        houseki_proofs::VerifyError,
    ),
}

impl From<houseki_proofs::VerifyError> for UnitPreparationError {
    /// Preserves local failure categories instead of manufacturing rejection receipts.
    fn from(error: houseki_proofs::VerifyError) -> Self {
        match error {
            houseki_proofs::VerifyError::Busy
            | houseki_proofs::VerifyError::AllocationFailed
            | houseki_proofs::VerifyError::BackendUnavailable => Self::Operational(error),
            _ => Self::InvalidProof(error),
        }
    }
}
