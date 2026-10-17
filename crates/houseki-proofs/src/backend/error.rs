//! Redacted failures from private proof preparation and execution.

/// Redacted failures from private backend preparation or execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendError {
    /// The operating system could not supply every required private seed.
    EntropyUnavailable,

    /// A bounded storage request could not be allocated.
    AllocationFailed,

    /// Cancellation discarded this attempt or its token had already been consumed.
    Cancelled,

    /// Private allocation protection or complete release accounting was unavailable.
    BackendUnavailable,

    /// Trace dimensions do not match the selected AIR or hiding floor.
    InvalidTrace,

    /// The pinned prover failed without returning a complete proof.
    ProvingFailed,

    /// Cryptographic verification or expected public dimensions failed.
    InvalidProof,
}
