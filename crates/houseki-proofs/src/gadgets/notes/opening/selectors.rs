//! Trusted invocation activity paired with the complete opening phase schedule.

/// External selectors that bound opening continuity and scratch liveness to one invocation.
pub(crate) struct Selectors<'a, E> {
    /// The existing seventy-eight fixed cycle selectors.
    pub(crate) phases: &'a [E],

    /// One throughout the complete invocation and zero during other gadget operations.
    pub(crate) active: E,
}
