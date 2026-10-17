//! Attempt scoped allocation tagging and complete backend release accounting.

mod account;
mod allocator;
mod cancelled;
mod checkpoint;
mod error;
#[cfg(test)]
mod inspect_allocator;
mod public_copy;
mod scope;
mod suspension;
#[cfg(test)]
mod test_control;
mod usage;

pub use allocator::ProofAllocator;
pub(crate) use cancelled::Cancelled;
pub(crate) use checkpoint::checkpoint;
pub(crate) use error::MemoryError;
pub(crate) use public_copy::public_copy;
pub(crate) use scope::Scope;
#[cfg(test)]
pub(crate) use test_control::{INTERRUPTED_AT, LAST_USAGE, interrupt_at};
pub(crate) use usage::Usage;

use account::Account;
use std::{cell::Cell, ptr};

thread_local! {
    /// Borrowed accounting owner kept alive by the current thread's Scope.
    static ACTIVE: Cell<*const Account> = const { Cell::new(ptr::null()) };
}

/// Real allocator behavior and independent attempt ownership checks.
#[cfg(test)]
mod tests {
    use super::inspect_allocator::{InspectAllocator, SAW_ZEROES};
    use super::*;
    use crate::CancellationToken;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Propagates cancellation from inner transform work rather than an operation boundary.
    #[test]
    fn inner_backend_checkpoint_interrupts_an_attempt() {
        let token = CancellationToken::new();
        let scope = Scope::enter(&token).unwrap();

        let result = std::panic::catch_unwind(|| {
            let private = std::hint::black_box(vec![81_u8; 4096]);

            token.cancel();
            p3_util::prover_runtime::checkpoint(p3_util::prover_runtime::Phase::Transform);

            drop(private);
        });

        assert!(result.is_err());
        drop(result);

        assert!(scope.finish().unwrap().wiped_bytes >= 4096);
    }

    /// Retains cleanup ownership when an allocation is released by a different thread.
    #[test]
    fn allocation_cleanup_follows_ownership_across_threads() {
        let transfer = std::sync::atomic::AtomicPtr::<[u8; 8192]>::new(std::ptr::null_mut());
        let completed = AtomicBool::new(false);

        std::thread::scope(|workers| {
            workers.spawn(|| {
                let pointer = loop {
                    let pointer = transfer.load(Ordering::Acquire);
                    if !pointer.is_null() {
                        break pointer;
                    }

                    std::thread::yield_now();
                };

                // Safety: The main thread transfers one unique Box with the same complete layout.
                drop(unsafe { Box::from_raw(pointer) });
                completed.store(true, Ordering::Release);
            });

            let token = CancellationToken::new();
            let scope = Scope::enter(&token).unwrap();

            transfer.store(Box::into_raw(Box::new([77_u8; 8192])), Ordering::Release);
            while !completed.load(Ordering::Acquire) {
                std::thread::yield_now();
            }

            assert!(scope.finish().unwrap().wiped_bytes >= 8192);
        });
    }

    /// Preserves alignment, retained bytes and the original allocation when growth cannot be represented.
    #[test]
    fn allocator_preserves_layout_and_failed_reallocation() {
        let token = CancellationToken::new();
        let scope = Scope::enter(&token).unwrap();
        let allocator = ProofAllocator::new(System);

        for alignment in [1, 2, 8, 64, 4096] {
            let original = Layout::from_size_align(17, alignment).unwrap();
            // Safety: Nonzero allocations are checked, initialized and released with their actual layouts.
            unsafe {
                let pointer = allocator.alloc_zeroed(original);
                assert!(!pointer.is_null());
                assert_eq!(pointer as usize % alignment, 0);
                assert_eq!(std::slice::from_raw_parts(pointer, 17), &[0; 17]);

                pointer.write_bytes(41, 17);
                assert!(allocator.realloc(pointer, original, usize::MAX).is_null());
                assert_eq!(std::slice::from_raw_parts(pointer, 17), &[41; 17]);

                let grown = allocator.realloc(pointer, original, 33);
                assert!(!grown.is_null());
                assert_eq!(grown as usize % alignment, 0);
                assert_eq!(std::slice::from_raw_parts(grown, 17), &[41; 17]);

                let shrunk =
                    allocator.realloc(grown, Layout::from_size_align(33, alignment).unwrap(), 9);
                assert!(!shrunk.is_null());
                assert_eq!(std::slice::from_raw_parts(shrunk, 9), &[41; 9]);

                allocator.dealloc(shrunk, Layout::from_size_align(9, alignment).unwrap());
            }
        }

        assert!(scope.finish().unwrap().wiped_bytes >= 5 * (17 + 33 + 9));
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
