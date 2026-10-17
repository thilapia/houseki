//! Attempt scoped allocation tagging and complete backend release accounting.

mod allocator;

pub use allocator::ProofAllocator;

use std::cell::Cell;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use crate::CancellationToken;

thread_local! {
    /// Borrowed accounting owner kept alive by the current thread's Scope.
    static ACTIVE: Cell<*const Account> = const { Cell::new(ptr::null()) };
}

/// Public counters and cancellation state retained until the last tagged allocation is released.
struct Account {
    /// Number of currently live tagged allocations.
    live: AtomicUsize,

    /// Number of successful tagged allocation requests.
    allocations: AtomicUsize,

    /// Currently allocated payload bytes, excluding allocator headers.
    bytes: AtomicUsize,

    /// Maximum simultaneously retained payload bytes.
    peak: AtomicUsize,

    /// Total payload bytes cleared before release.
    wiped: AtomicUsize,

    /// Shared monotonic cancellation request for this attempt.
    cancelled: Arc<AtomicBool>,
}

impl Account {
    /// Records a successful request without allocating or panicking inside the allocator.
    fn allocated(&self, size: usize) {
        self.live.fetch_add(1, Ordering::Relaxed);
        self.allocations.fetch_add(1, Ordering::Relaxed);
        let bytes = self
            .bytes
            .fetch_add(size, Ordering::Relaxed)
            .saturating_add(size);
        self.peak.fetch_max(bytes, Ordering::Relaxed);
    }

    /// Records cleanup only after volatile stores have cleared the complete payload.
    fn released(&self, size: usize) {
        self.wiped.fetch_add(size, Ordering::Relaxed);
        self.bytes.fetch_sub(size, Ordering::Relaxed);
        self.live.fetch_sub(1, Ordering::Release);
    }
}

/// Redacted failures of private attempt ownership and lifecycle validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemoryError {
    /// A token was cancelled or already consumed by another attempt.
    Cancelled,

    /// The current thread already owns an attempt scope.
    NestedAttempt,

    /// The selected global allocator did not tag the installation probe.
    BackendUnavailable,

    /// Tagged storage remained live at the operation boundary.
    OutstandingAllocations,

    /// Fallible public output allocation failed.
    AllocationFailed,
}

/// Observed release accounting for a completed attempt, without private values.
#[derive(Debug)]
pub(crate) struct Usage {
    /// Maximum simultaneously retained tagged payload bytes.
    pub(crate) peak_bytes: usize,

    /// Total payload bytes cleared before their storage was released.
    pub(crate) wiped_bytes: usize,
}

/// Thread-bound ownership boundary spanning all private backend allocations.
pub(crate) struct Scope {
    /// Accounting kept alive independently by every tagged allocation.
    account: Arc<Account>,

    /// Prevents moving the active thread-local boundary to a different thread.
    thread: PhantomData<Rc<()>>,
}

impl Scope {
    /// Claims one token and checks allocator installation before admitting private work.
    pub(crate) fn enter(token: &CancellationToken) -> Result<Self, MemoryError> {
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
        Ok(Usage {
            peak_bytes: self.account.peak.load(Ordering::Relaxed),
            wiped_bytes: self.account.wiped.load(Ordering::Relaxed),
        })
    }
}

impl Drop for Scope {
    /// Detaches thread-local accounting while allocation headers retain their cleanup owners.
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(ptr::null()));
    }
}

/// A typed cancellation unwind payload containing no witness values or backend diagnostics.
#[derive(Debug)]
pub(crate) struct Cancelled;

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

/// Restores allocation tagging after copying an explicitly public result.
struct Suspension {
    /// Still-live attempt restored when this stack guard leaves scope.
    account: *const Account,
}

impl Drop for Suspension {
    /// Restores the same thread's attempt even if public output construction unwinds.
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(self.account));
    }
}

/// Copies only canonical public proof bytes outside the private allocation lifetime.
///
/// Callers must never use this escape for witnesses, traces or backend intermediate data.
pub(crate) fn public_copy(bytes: &[u8]) -> Result<Vec<u8>, MemoryError> {
    let account = ACTIVE.with(|active| active.replace(ptr::null()));
    let _suspension = Suspension { account };
    let mut result = Vec::new();
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| MemoryError::AllocationFailed)?;
    result.extend_from_slice(bytes);
    Ok(result)
}

/// Real allocator behavior and independent attempt ownership checks.
#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Records the observed bytes immediately before the underlying allocator releases them.
    static SAW_ZEROES: AtomicBool = AtomicBool::new(true);

    /// Checks a fixed aligned fixture after the production allocator has cleared its payload.
    struct InspectAllocator;

    // Safety: This test allocator forwards unchanged allocations to System and only reads live storage.
    unsafe impl GlobalAlloc for InspectAllocator {
        /// Allocates the exact requested system layout.
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // Safety: The caller supplies a valid allocation layout.
            unsafe { System.alloc(layout) }
        }

        /// Inspects initialized fixture bytes before forwarding their deallocation.
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // Safety: The fixture uses alignment 64 with a payload spanning the remainder.
            let bytes = unsafe { std::slice::from_raw_parts(pointer.add(64), layout.size() - 64) };
            if bytes.iter().any(|byte| *byte != 0) {
                SAW_ZEROES.store(false, Ordering::Relaxed);
            }
            // Safety: The original pointer and layout are forwarded unchanged.
            unsafe { System.dealloc(pointer, layout) }
        }
    }

    /// Wipes the original and replacement allocations before either reaches the underlying allocator.
    #[test]
    fn allocator_wipes_reallocated_and_released_backend_storage() {
        let token = crate::CancellationToken::new();
        let scope = Scope::enter(&token).unwrap();
        let allocator = ProofAllocator::new(InspectAllocator);
        let layout = Layout::from_size_align(256, 64).unwrap();
        // Safety: Both allocations are checked before access and released using their exact layouts.
        unsafe {
            let pointer = allocator.alloc(layout);
            assert!(!pointer.is_null());
            pointer.write_bytes(0x57, 256);
            let grown = allocator.realloc(pointer, layout, 512);
            assert!(!grown.is_null());
            assert_eq!(std::slice::from_raw_parts(grown, 256), &[0x57; 256]);
            grown.write_bytes(0xa3, 512);
            allocator.dealloc(grown, Layout::from_size_align(512, 64).unwrap());
        }
        let usage = scope.finish().unwrap();
        assert!(usage.wiped_bytes >= 768);
        assert!(usage.peak_bytes >= 768);
        assert!(SAW_ZEROES.load(Ordering::Relaxed));
    }

    /// Allows only an explicitly copied public result to outlive private allocation cleanup.
    #[test]
    fn public_result_does_not_retain_private_attempt_allocations() {
        let token = crate::CancellationToken::new();
        let scope = Scope::enter(&token).unwrap();
        let public = vec![3_u8; 257];
        let result = public_copy(&public).unwrap();
        drop(public);
        assert!(scope.finish().unwrap().wiped_bytes >= 257);
        assert_eq!(result, [3; 257]);
    }

    /// Refuses completion when an attempt allocation survives its operation boundary.
    #[test]
    fn retained_allocations_cannot_be_reported_as_cleaned() {
        let token = crate::CancellationToken::new();
        let scope = Scope::enter(&token).unwrap();
        let escaped = std::hint::black_box(vec![91_u8; 1024]);
        assert!(matches!(
            scope.finish(),
            Err(MemoryError::OutstandingAllocations)
        ));
        drop(escaped);
    }

    /// Releases every owned allocation while unwinding an interrupted operation.
    #[test]
    fn cancellation_unwinds_and_clears_attempt_allocations() {
        let token = crate::CancellationToken::new();
        let scope = Scope::enter(&token).unwrap();
        let result = std::panic::catch_unwind(|| {
            let private = std::hint::black_box(vec![73_u8; 2048]);
            token.cancel();
            checkpoint();
            std::hint::black_box(private);
        });
        assert!(result.is_err());
        drop(result);
        assert!(scope.finish().unwrap().wiped_bytes >= 2048);
        assert!(matches!(Scope::enter(&token), Err(MemoryError::Cancelled)));
    }

    /// Accounts for each worker independently and prevents nested attempt ownership.
    #[test]
    fn independent_jobs_do_not_share_witness_buffers() {
        let jobs = [4096, 8192].map(|size| {
            std::thread::spawn(move || {
                let token = crate::CancellationToken::new();
                let scope = Scope::enter(&token).unwrap();
                assert!(matches!(
                    Scope::enter(&crate::CancellationToken::new()),
                    Err(MemoryError::NestedAttempt)
                ));
                let private = std::hint::black_box(vec![19_u8; size]);
                drop(private);
                scope.finish().unwrap().wiped_bytes
            })
        });
        let [first, second] = jobs.map(|job| job.join().unwrap());
        assert_eq!(second - first, 4096);
    }
}
