//! Test only allocator measurements scoped to the calling test thread.

mod measurement;

use measurement::Measurement;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Active allocation call count and requested bytes for this thread alone.
    static COUNTS: Cell<Option<(usize, usize)>> = const { Cell::new(None) };

    /// Live initialized payload range and its observed cleanup result.
    static WATCH: Cell<Option<(usize, usize, bool)>> = const { Cell::new(None) };
}

/// System allocator with an optional thread local observation window.
struct MeasuredAllocator;

/// Measures only explicitly selected decoder calls without changing allocator behavior.
#[global_allocator]
static ALLOCATOR: crate::memory::ProofAllocator<MeasuredAllocator> =
    crate::memory::ProofAllocator::new(MeasuredAllocator);

/// Records a request without allocating or accessing another thread's measurement.
fn record(bytes: usize) {
    let _ = COUNTS.try_with(|counts| {
        if let Some((calls, total)) = counts.get() {
            counts.set(Some((calls + 1, total + bytes)));
        }
    });
}

// Safety: Every operation forwards the unchanged pointer and layout to the system allocator.
unsafe impl GlobalAlloc for MeasuredAllocator {
    /// Records an ordinary allocation before forwarding its exact layout.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());

        // Safety: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    /// Releases the original system allocation without counting a new request.
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = WATCH.try_with(|watch| {
            if let Some((start, length, _)) = watch.get() {
                let base = pointer as usize;
                if start >= base && start + length <= base + layout.size() {
                    // Safety: The test registers initialized bytes within this still-live allocation.
                    let bytes = unsafe { std::slice::from_raw_parts(start as *const u8, length) };

                    watch.set(Some((start, length, bytes.iter().all(|byte| *byte == 0))));
                }
            }
        });

        // Safety: Both values are forwarded unchanged from the allocator caller.
        unsafe { System.dealloc(pointer, layout) }
    }

    /// Preserves the system allocator's zero initialization contract.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());

        // Safety: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc_zeroed(layout) }
    }

    /// Records the complete replacement request without changing reallocation semantics.
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);

        // Safety: All original arguments are forwarded unchanged.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

/// Returns the result, allocation request count and total requested bytes for one operation.
pub(crate) fn measure<T>(operation: impl FnOnce() -> T) -> (T, usize, usize) {
    COUNTS.with(|counts| {
        assert!(counts.get().is_none());
        counts.set(Some((0, 0)));
    });

    let measurement = Measurement;

    let result = operation();

    let (calls, bytes) = COUNTS.with(|counts| counts.get().unwrap());
    drop(measurement);

    (result, calls, bytes)
}

/// Watches an initialized live allocation range until the supplied drop operation releases it.
///
/// # Safety
///
/// The pointer and length must describe initialized storage owned until the operation releases it.
pub(crate) unsafe fn observes_zeroed_drop(
    pointer: *const u8,
    length: usize,
    operation: impl FnOnce(),
) -> bool {
    WATCH.with(|watch| watch.set(Some((pointer as usize, length, false))));

    operation();

    WATCH.with(|watch| watch.take().unwrap().2)
}
