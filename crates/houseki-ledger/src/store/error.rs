//! Publication conflict and prepublication local storage failures.

/// A publication attempt failed without changing the current complete store image.
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// Another candidate already consumed the expected parent.
    #[error("checkpoint parent changed")]
    ParentChanged,

    /// Private candidate or retained native history violates its integrity contract.
    #[error("checkpoint publication integrity failure")]
    Integrity,

    /// Local archive/index allocation failed before the atomic ownership swap.
    #[error("checkpoint publication allocation failed")]
    Allocation,

    /// Complete canonical comparison or replay representation failed.
    #[error(transparent)]
    Artifact(#[from] crate::ArtifactError),
}

/// Public input replay failed before a reported checkpoint could be reproduced.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// Archive identity or a recomputed complete checkpoint differs from the expected record.
    #[error("replay mismatch: {0}")]
    Mismatch(&'static str),

    /// Independent bootstrap validation failed.
    #[error(transparent)]
    Bootstrap(#[from] crate::BootstrapError),

    /// Complete public source binding could not be revalidated.
    #[error(transparent)]
    Order(#[from] crate::OrderError),

    /// Fresh cryptographic authorization failed.
    #[error(transparent)]
    Unit(#[from] crate::UnitPreparationError),

    /// Complete checkpoint preparation failed.
    #[error(transparent)]
    Preparation(#[from] crate::PreparationError),

    /// Atomic publication of a recomputed candidate failed.
    #[error(transparent)]
    Commit(#[from] CommitError),

    /// A public canonical comparison failed.
    #[error(transparent)]
    Artifact(#[from] crate::ArtifactError),
}
