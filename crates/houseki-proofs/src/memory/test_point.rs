//! Public schedule locations used only by deterministic cleanup tests.

/// A component boundary identified by public slot indices without witness data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestPoint {
    /// Imported input ownership before opening construction.
    #[cfg(feature = "prover")]
    InputOpening(usize),

    /// Input opening completed before spending authority construction.
    #[cfg(feature = "prover")]
    InputAuthority(usize),

    /// Input authority completed before occupied membership construction.
    #[cfg(feature = "prover")]
    InputMembership(usize),

    /// Complete input before its single total update.
    #[cfg(feature = "prover")]
    InputAccumulation(usize),

    /// Imported output ownership before opening construction.
    #[cfg(feature = "prover")]
    OutputOpening(usize),

    /// Complete output before its single total update.
    #[cfg(feature = "prover")]
    OutputAccumulation(usize),

    /// Complete note processing before the once-only public fee update.
    #[cfg(feature = "prover")]
    Fee,

    /// Complete backend proof before bounded canonical encoding.
    Encoding,

    /// Inner backend arithmetic reached through the installed protected callback.
    Backend(p3_util::prover_runtime::Phase),
}
