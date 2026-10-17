//! Aligned metadata retaining allocation cleanup ownership.

use super::super::Account;
use std::alloc::Layout;

/// Metadata preceding an aligned payload and retaining its accounting owner until deallocation.
pub(super) struct Header {
    /// Strong Arc reference represented as a raw pointer, or null for an ordinary allocation.
    pub(super) account: *const Account,
}

/// Computes the same header and payload layout for allocation and release.
pub(super) fn expanded(layout: Layout) -> Option<(Layout, usize)> {
    let (combined, offset) = Layout::new::<Header>().extend(layout).ok()?;

    Some((combined.pad_to_align(), offset))
}
