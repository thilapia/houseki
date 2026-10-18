//! Borrowed assignment sources from guarded native spend conversion.

use p3_goldilocks::Goldilocks;

/// Borrows sources without creating another private owner or retaining them after assignment.
pub(crate) struct Input<'a> {
    /// Original protected spending secret bytes.
    pub(crate) spending_key: &'a [Goldilocks; 32],

    /// Original protected nullifier secret bytes.
    pub(crate) nullifier_key: &'a [Goldilocks; 32],

    /// Expected network bytes.
    pub(crate) network: &'a [Goldilocks; 64],

    /// Complete note commitment shared with opening and membership.
    pub(crate) commitment: &'a [Goldilocks; 64],

    /// Original position shared with membership, in little endian order.
    pub(crate) position: &'a [Goldilocks; 8],
}
