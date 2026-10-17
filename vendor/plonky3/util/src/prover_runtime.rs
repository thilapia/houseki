//! Optional cooperative interruption at arithmetic loop boundaries.

/// Public phase names contain no witness data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Field transform butterflies and permutations.
    Transform,
    /// Constraint row groups.
    Constraint,
    /// Merkle hashing and commitment preparation.
    Commitment,
    /// Opening reduction and query construction.
    Opening,
    /// Low degree folding rows.
    Fold,
    /// Private random stream sampling.
    Random,
}

/// Runs the current thread's callback when the optional runtime is enabled.
#[inline]
pub fn checkpoint(phase: Phase) {
    #[cfg(feature = "prover-runtime")]
    runtime::CHECKPOINT.with(|slot| {
        if let Some(callback) = slot.get() {
            callback(phase);
        }
    });
    #[cfg(not(feature = "prover-runtime"))]
    let _ = phase;
}

/// Discards a private debug constraint failure without invoking an application panic hook.
///
/// Ordinary upstream consumers retain their usual diagnostics when no callback is installed.
pub fn redact_failure() {
    #[cfg(feature = "prover-runtime")]
    runtime::CHECKPOINT.with(|slot| {
        if slot.get().is_some() {
            std::panic::resume_unwind(alloc::boxed::Box::new(()));
        }
    });
}

#[cfg(feature = "prover-runtime")]
pub use runtime::{Guard, install};

/// Thread confined callback registration with automatic restoration.
#[cfg(feature = "prover-runtime")]
mod runtime {
    use super::Phase;
    use core::{cell::Cell, marker::PhantomData};
    use std::rc::Rc;

    std::thread_local! {
        /// Current thread's callback without heap allocation.
        pub(super) static CHECKPOINT: Cell<Option<fn(Phase)>> = const { Cell::new(None) };
    }

    /// Restores a prior callback on the thread that installed it.
    pub struct Guard {
        /// Callback that was active before installation.
        previous: Option<fn(Phase)>,
        /// Prevents moving restoration to another thread.
        thread: PhantomData<Rc<()>>,
    }

    /// Installs a callback whose unwinding releases ordinary backend owners.
    pub fn install(callback: fn(Phase)) -> Guard {
        Guard {
            previous: CHECKPOINT.with(|slot| slot.replace(Some(callback))),
            thread: PhantomData,
        }
    }

    impl Drop for Guard {
        /// Restores the enclosing registration during normal return or unwinding.
        fn drop(&mut self) {
            CHECKPOINT.with(|slot| slot.set(self.previous));
        }
    }
}
