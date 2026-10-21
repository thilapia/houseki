//! Complete checkpoint preparation failures with no partial publication.

/// A candidate cannot be completed and the committed parent remains untouched.
#[derive(Debug, thiserror::Error)]
pub enum PreparationError {
    /// A supposedly trusted parent or computed record relation is inconsistent.
    #[error("checkpoint integrity failure")]
    Integrity,

    /// Local bookkeeping allocation failed before a complete candidate could escape.
    #[error("checkpoint allocation failed")]
    Allocation,

    /// Whole unit authorization is incompatible with the parent interpretation.
    #[error(transparent)]
    Unit(
        /// Original unit failure retained as the source.
        #[from]
        crate::UnitPreparationError,
    ),

    /// The canonical source cannot continue from the persisted cursor.
    #[error(transparent)]
    Order(
        /// Original order failure retained as the source.
        #[from]
        crate::OrderError,
    ),

    /// Checkpoint progression or policy derivation failed.
    #[error(transparent)]
    Policy(
        /// Original policy failure retained as the source.
        #[from]
        crate::PolicyError,
    ),

    /// Working state reconstruction or application failed.
    #[error(transparent)]
    State(
        /// Original state failure retained as the source.
        #[from]
        crate::StateError,
    ),

    /// Ordered state evaluation failed locally.
    #[error(transparent)]
    Execution(
        /// Original execution failure retained as the source.
        #[from]
        crate::ExecutionError,
    ),

    /// Complete canonical artifact representation failed.
    #[error(transparent)]
    Artifact(
        /// Original artifact failure retained as the source.
        #[from]
        crate::ArtifactError,
    ),

    /// Fixed native commitment construction failed.
    #[error(transparent)]
    Hash(
        /// Original hash failure retained as the source.
        #[from]
        houseki_crypto::CryptoFramingError,
    ),
}
