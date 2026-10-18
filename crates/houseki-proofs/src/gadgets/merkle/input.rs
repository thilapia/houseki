//! Borrowed protected membership assignment fields.

use p3_goldilocks::Goldilocks;

/// Borrows the original path and linked fields without another private owner.
pub(crate) struct Input<'a> {
    /// Expected network bytes.
    pub(crate) network: &'a [Goldilocks; 64],

    /// Complete occupied count in little endian order.
    pub(crate) count: &'a [Goldilocks; 16],

    /// Commitment shared with the opening and authority relations.
    pub(crate) commitment: &'a [Goldilocks; 64],

    /// Original position shared with nullifier derivation.
    pub(crate) position: &'a [Goldilocks; 8],

    /// Protected siblings in leaf-to-root order.
    pub(crate) siblings: &'a [[Goldilocks; 64]; 64],
}
