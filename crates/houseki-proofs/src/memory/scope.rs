//! Thread bound ownership spanning private backend work and release accounting.

#[cfg(test)]
use super::LAST_USAGE;
use super::{ACTIVE, Account, MemoryError, Usage, checkpoint::backend_checkpoint};
use crate::CancellationToken;
use std::{
    marker::PhantomData,
    ptr,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Thread bound ownership boundary spanning all private backend allocations.
pub(crate) struct Scope {
    /// Accounting kept alive independently by every tagged allocation.
    account: Arc<Account>,

    /// Prevents moving the active thread local boundary to a different thread.
    thread: PhantomData<Rc<()>>,

    /// Restores backend callbacks when this attempt leaves its worker thread.
    _checkpoints: p3_util::prover_runtime::Guard,
}

impl Scope {
    /// Claims one token and checks allocator installation before admitting private work.
    pub(crate) fn enter(token: &CancellationToken) -> Result<Self, MemoryError> {
        if p3_maybe_rayon::PARALLEL_ENABLED || !cfg!(panic = "unwind") {
            return Err(MemoryError::BackendUnavailable);
        }

        if ACTIVE.with(|active| !active.get().is_null()) {
            return Err(MemoryError::NestedAttempt);
        }

        if !token.claim() {
            return Err(MemoryError::Cancelled);
        }

        let account = Arc::new(Account {
            live: AtomicUsize::new(0),
            allocations: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            wiped: AtomicUsize::new(0),
            cancelled: Arc::clone(&token.cancelled),
        });

        ACTIVE.with(|active| active.set(Arc::as_ptr(&account)));
        let scope = Self {
            account,
            thread: PhantomData,
            _checkpoints: p3_util::prover_runtime::install(backend_checkpoint),
        };

        let probe = Box::new(0_u8);
        std::hint::black_box(&probe);
        drop(probe);
        if scope.account.allocations.load(Ordering::Relaxed) == 0 {
            return Err(MemoryError::BackendUnavailable);
        }

        Ok(scope)
    }

    /// Confirms that every tagged allocation was released before producing completion evidence.
    pub(crate) fn finish(self) -> Result<Usage, MemoryError> {
        if self.account.live.load(Ordering::Acquire) != 0 {
            return Err(MemoryError::OutstandingAllocations);
        }

        #[cfg(test)]
        LAST_USAGE.with(|usage| {
            usage.set(Some((
                self.account.peak.load(Ordering::Relaxed),
                self.account.wiped.load(Ordering::Relaxed),
            )))
        });

        Ok(Usage {
            peak_bytes: self.account.peak.load(Ordering::Relaxed),
            wiped_bytes: self.account.wiped.load(Ordering::Relaxed),
        })
    }
}

impl Drop for Scope {
    /// Detaches thread local accounting while allocation headers retain their cleanup owners.
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(ptr::null()));
    }
}
