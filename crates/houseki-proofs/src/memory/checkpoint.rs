//! Cooperative cancellation inside private backend phases.

use std::sync::atomic::Ordering;

#[cfg(test)]
use super::test_control::{INTERRUPT, INTERRUPTED_AT};
use super::{ACTIVE, Cancelled};

/// Applies backend interruption without allocating diagnostics or exposing private values.
pub(super) fn backend_checkpoint(phase: p3_util::prover_runtime::Phase) {
    #[cfg(test)]
    INTERRUPT.with(|slot| {
        if let Some((selected, left, failure)) = slot.get()
            && selected == phase
        {
            if left == 0 {
                slot.set(None);
                INTERRUPTED_AT.with(|time| time.set(Some(std::time::Instant::now())));

                if failure {
                    std::panic::resume_unwind(Box::new(()));
                }

                ACTIVE.with(|active| {
                    // Safety: Only an active Scope installs this callback on its own thread.
                    unsafe { &*active.get() }
                        .cancelled
                        .store(true, Ordering::Release);
                });
            } else {
                slot.set(Some((selected, left - 1, failure)));
            }
        }
    });
    #[cfg(not(test))]
    let _ = phase;

    checkpoint();
}

/// Stops at a cooperative checkpoint without invoking the process panic hook.
pub(crate) fn checkpoint() {
    let cancelled = ACTIVE.with(|active| {
        let account = active.get();

        // Safety: An active Scope on this thread keeps the account alive during the callback.
        !account.is_null() && unsafe { &*account }.cancelled.load(Ordering::Acquire)
    });
    if cancelled {
        std::panic::resume_unwind(Box::new(Cancelled));
    }
}
