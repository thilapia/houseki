//! Fixture source provenance and deterministic range failures.

/// A complete source cannot be authenticated or continued under fixture trust.
#[derive(Debug, thiserror::Error)]
pub enum OrderError {
    /// A source list, component byte total or host conversion exceeds reference bounds.
    #[error("fixture source bound exceeded")]
    Bound,

    /// Complete source identity, committee, origin or continuation binding differs.
    #[error("invalid fixture source binding")]
    Binding,

    /// The same origin appears twice in the finite stream.
    #[error("duplicate fixture occurrence origin")]
    DuplicateOrigin,

    /// One complete occurrence cannot fit into any checkpoint range.
    #[error("source unit contains an unsliceable occurrence")]
    UnitInadmissible,

    /// The finite source has no unconsumed successor.
    #[error("fixture source is exhausted")]
    SourceExhausted,

    /// Local bounded storage could not be reserved.
    #[error("fixture allocation failed")]
    Allocation,

    /// Canonical representation validation failed.
    #[error(transparent)]
    Artifact(
        /// Original artifact failure retained as the source.
        #[from]
        crate::ArtifactError,
    ),

    /// A fixed source commitment could not be constructed.
    #[error(transparent)]
    Hash(
        /// Original hash failure retained as the source.
        #[from]
        houseki_crypto::CryptoFramingError,
    ),
}
