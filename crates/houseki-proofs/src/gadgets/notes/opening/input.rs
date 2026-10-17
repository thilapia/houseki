//! Borrowed opening bytes without validation, allocation or transferred cleanup ownership.

use p3_goldilocks::Goldilocks;

/// Raw canonical-layout fields borrowed while their original protected owners remain alive.
///
/// Constructing this view does not validate bytes or establish any constraint relation.
pub(crate) struct Input<'a> {
    /// Complete little endian note version identifier.
    pub(super) version: &'a [Goldilocks; 4],

    /// Address version, network, suite, ownership and full key in native recipient order.
    pub(super) recipient: &'a [Goldilocks; 1704],

    /// Sixteen little endian amount limbs.
    pub(super) amount: &'a [Goldilocks; 16],

    /// Blinding bytes retained by the caller's owner.
    pub(super) blinding: &'a [Goldilocks; 32],
}

impl<'a> Input<'a> {
    /// Borrows the native adapter's existing slices without copying private fields.
    pub(crate) fn new(
        version: &'a [Goldilocks; 4],
        recipient: &'a [Goldilocks; 1704],
        amount: &'a [Goldilocks; 16],
        blinding: &'a [Goldilocks; 32],
    ) -> Self {
        Self {
            version,
            recipient,
            amount,
            blinding,
        }
    }
}
