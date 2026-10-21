//! Operational and integrity failures distinct from canonical state rejection.

/// A local execution failure aborts the complete prepared checkpoint.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    /// An invariant promised by immutable authorization or parent state was violated.
    #[error("execution integrity failure")]
    Integrity,

    /// The current working state cannot continue after a local application error.
    #[error(transparent)]
    State(#[from] crate::StateError),

    /// Exact fee arithmetic or policy interpretation failed unexpectedly.
    #[error(transparent)]
    Policy(#[from] crate::PolicyError),
}
