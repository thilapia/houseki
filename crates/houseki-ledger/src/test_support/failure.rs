//! Thread-local fault injection at actual disposable-state and publication boundaries.

use std::cell::Cell;

/// One observable stage boundary in the reference executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailurePoint {
    /// A reconstructed working tree has completed.
    Reconstruct,

    /// One original-order nullifier was inserted.
    NullifierInsert(usize),

    /// One original-order output was appended.
    NoteAppend(usize),

    /// One coalesced account replacement was staged.
    AccountReplace(usize),

    /// Shielded accounting was replaced.
    PoolReplace,

    /// Canonical anchor history was pruned.
    AnchorPrune,

    /// One named commitment completed.
    Commitment(&'static str),

    /// The complete immutable candidate is about to be sealed.
    Seal,

    /// A complete store archive has been constructed.
    ArchiveReserve,

    /// No fallible publication work remains.
    Publish,
}

thread_local! {
    /// Fault selected only by private tests on the current test thread.
    static SELECTED:Cell<Option<FailurePoint>>=const{Cell::new(None)};
}

/// Installs one private test fault until the returned scope guard is dropped.
pub(crate) fn inject(point: FailurePoint) -> Injection {
    SELECTED.set(Some(point));
    Injection
}

/// Restores normal execution even when a test assertion unwinds.
pub(crate) struct Injection;

impl Drop for Injection {
    /// Removes this thread's selected test failure.
    fn drop(&mut self) {
        SELECTED.set(None)
    }
}

/// Reports whether this actual boundary should fail locally in the current test.
pub(crate) fn hit(point: FailurePoint) -> bool {
    SELECTED.get() == Some(point)
}
