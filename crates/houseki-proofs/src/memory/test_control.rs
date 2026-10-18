//! Deterministic interruption and cleanup observations for backend lifecycle tests.

use super::{ACTIVE, MemoryError, TestPoint};
use std::{cell::Cell, sync::atomic::Ordering};

thread_local! {
    /// One selected payment boundary and whether to fail a recoverable allocation there.
    static PAYMENT_INTERRUPT: Cell<Option<(TestPoint, bool)>> = const { Cell::new(None) };

    /// Test only deterministic interruption inside a selected arithmetic phase.
    pub(super) static INTERRUPT: Cell<Option<(p3_util::prover_runtime::Phase, usize, bool)>> = const { Cell::new(None) };

    /// Time at which an inner checkpoint observed the synthetic request.
    pub(crate) static INTERRUPTED_AT: Cell<Option<std::time::Instant>> = const { Cell::new(None) };

    /// Largest live payload observed at transform, constraint, commitment, opening, fold and random checkpoints.
    pub(crate) static PHASE_BYTES: Cell<[usize; 6]> = const { Cell::new([0; 6]) };

    /// Observed accounting from the last fully released attempt on this test thread.
    pub(crate) static LAST_USAGE: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}

/// Arms one synthetic interrupt without changing production cancellation behavior.
pub(crate) fn interrupt_at(phase: p3_util::prover_runtime::Phase, after: usize, failure: bool) {
    INTERRUPT.with(|slot| slot.set(Some((phase, after, failure))));
    LAST_USAGE.with(|usage| usage.set(None));
}

/// Arms a public component boundary without retaining any private owner.
#[cfg(all(feature = "prover", feature = "experimental-profiles"))]
pub(crate) fn interrupt_payment_at(point: TestPoint, allocation_failure: bool) {
    PAYMENT_INTERRUPT.with(|selected| selected.set(Some((point, allocation_failure))));
    LAST_USAGE.with(|usage| usage.set(None));
}

/// Exercises real fallible allocation failure or cooperative cancellation at a selected boundary.
///
/// Opening and encoding hooks fail their actual next fallible reservation.
///
/// Other hooks use a fallible probe while earlier private buffers are live and do not claim
/// recovery from an infallible allocator abort.
pub(crate) fn at_payment_point(point: TestPoint) {
    PAYMENT_INTERRUPT.with(|selected| {
        if let Some((expected, allocation_failure)) = selected.get()
            && expected == point
        {
            selected.set(None);
            if allocation_failure {
                crate::test_allocator::fail_next_allocation();
                if point == TestPoint::Encoding {
                    // The encoder's next allocation is its real fallible exact byte reservation.
                    return;
                }

                #[cfg(feature = "prover")]
                if matches!(
                    point,
                    TestPoint::InputOpening(_) | TestPoint::OutputOpening(_)
                ) {
                    // The next allocation is the actual guarded opening trace reservation.
                    return;
                }

                let mut probe = Vec::<u8>::new();
                assert!(probe.try_reserve_exact(256).is_err());
                std::panic::resume_unwind(Box::new(MemoryError::AllocationFailed));
            }

            ACTIVE.with(|active| {
                // Safety: These hooks run only inside the current thread's active protected attempt.
                unsafe { &*active.get() }
                    .cancelled
                    .store(true, Ordering::Release);
            });
            super::checkpoint();
        }
    });
}
