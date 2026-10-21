//! Thread local fault injection at actual disposable state and publication boundaries.

mod injection;

use injection::Injection;
use std::cell::Cell;

/// One observable stage boundary in the reference executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailurePoint {
    /// A reconstructed working tree has completed.
    Reconstruct,

    /// One original order nullifier was inserted.
    NullifierInsert(
        /// Zero based index of the inserted nullifier.
        usize,
    ),

    /// One original order output was appended.
    NoteAppend(
        /// Zero based index of the appended note.
        usize,
    ),

    /// One coalesced account replacement was staged.
    AccountReplace(
        /// Zero based index of the replaced account.
        usize,
    ),

    /// Shielded accounting was replaced.
    PoolReplace,

    /// Canonical anchor history was pruned.
    AnchorPrune,

    /// One named commitment completed.
    Commitment(
        /// Name of the commitment whose construction has completed.
        &'static str,
    ),

    /// The complete immutable candidate is about to be sealed.
    Seal,

    /// A complete store archive has been constructed.
    ArchiveReserve,

    /// No fallible publication work remains.
    Publish,
}

thread_local! {
    /// Fault selected only by private tests on the current test thread.
    static SELECTED: Cell<Option<FailurePoint>> = const { Cell::new(None) };
}

/// Installs one private test fault until the returned scope guard is dropped.
pub(crate) fn inject(point: FailurePoint) -> Injection {
    SELECTED.set(Some(point));
    Injection
}

/// Reports whether this actual boundary should fail locally in the current test.
pub(crate) fn hit(point: FailurePoint) -> bool {
    SELECTED.get() == Some(point)
}
