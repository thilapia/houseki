//! Stable links from complete payment composition into occupied membership.

/// Borrowed byte expressions shared by every membership phase.
pub(crate) struct Endpoints<'a, T> {
    /// Expected network for every hash.
    pub(crate) network: &'a [T; 64],

    /// Complete expected occupied count through 2^64.
    pub(crate) count: &'a [T; 16],

    /// Private commitment of the same input opening.
    pub(crate) commitment: &'a [T; 64],

    /// Original private position shared with nullifier derivation.
    pub(crate) position: &'a [T; 8],

    /// Complete expected public anchor root.
    pub(crate) root: &'a [T; 64],
}
