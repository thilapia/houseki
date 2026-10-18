//! Borrowed relation links shared with opening and membership composition.

/// Exact external byte expressions used throughout a complete spend invocation.
pub(crate) struct Endpoints<'a, T> {
    /// Expected network shared by every native hash.
    pub(crate) network: &'a [T; 64],

    /// Ownership from the same input opening.
    pub(crate) ownership: &'a [T; 64],

    /// Commitment from the same input opening and occupied leaf.
    pub(crate) commitment: &'a [T; 64],

    /// Original private position shared with membership selection.
    pub(crate) position: &'a [T; 8],

    /// Expected public marker for this ordered input slot.
    pub(crate) nullifier: &'a [T; 64],
}
