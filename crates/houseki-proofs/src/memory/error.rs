//! Redacted failures of private attempt ownership and cleanup.

/// Redacted failures of private attempt ownership and lifecycle validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemoryError {
    /// A token was cancelled or already consumed by another attempt.
    Cancelled,

    /// The current thread already owns an attempt scope.
    NestedAttempt,

    /// The selected global allocator did not tag the installation probe.
    BackendUnavailable,

    /// Tagged storage remained live at the operation boundary.
    OutstandingAllocations,

    /// Fallible public output allocation failed.
    AllocationFailed,
}
