//! Failures to acquire the shared proof runtime slot.

/// Failure to acquire the shared runtime operation slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    /// Another proving or verification operation already owns this runtime.
    #[error("proof runtime is busy")]
    Busy,

    /// The process allocator does not provide the required private attempt cleanup boundary.
    #[cfg(feature = "prover")]
    #[error("protected prover allocator is unavailable")]
    BackendUnavailable,
}
