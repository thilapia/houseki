//! State integrity and local reconstruction failures.

/// A failure that prevents preparing a complete working checkpoint.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// A represented state exceeds its committed resource policy.
    #[error("state capacity exceeded")]
    Capacity,

    /// Accounting does not conserve the bounded issued total.
    #[error("ledger conservation failed")]
    Conservation,

    /// Reconstructed leaves or complete map keys disagree with the retained state.
    #[error("inconsistent logical state")]
    Integrity,

    /// Local storage could not be reserved.
    #[error("state allocation failed")]
    Allocation,

    /// The underlying tree could not complete construction or append.
    #[error(transparent)]
    Tree(#[from] houseki_state::NoteTreeError),
}
