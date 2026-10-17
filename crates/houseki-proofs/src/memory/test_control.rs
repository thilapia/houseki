//! Deterministic interruption and cleanup observations for backend lifecycle tests.

use std::cell::Cell;

thread_local! {
    /// Test only deterministic interruption inside a selected arithmetic phase.
    pub(super) static INTERRUPT: Cell<Option<(p3_util::prover_runtime::Phase, usize, bool)>> = const { Cell::new(None) };

    /// Time at which an inner checkpoint observed the synthetic request.
    pub(crate) static INTERRUPTED_AT: Cell<Option<std::time::Instant>> = const { Cell::new(None) };

    /// Observed accounting from the last fully released attempt on this test thread.
    pub(crate) static LAST_USAGE: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}

/// Arms one synthetic interrupt without changing production cancellation behavior.
pub(crate) fn interrupt_at(phase: p3_util::prover_runtime::Phase, after: usize, failure: bool) {
    INTERRUPT.with(|slot| slot.set(Some((phase, after, failure))));
    LAST_USAGE.with(|usage| usage.set(None));
}
