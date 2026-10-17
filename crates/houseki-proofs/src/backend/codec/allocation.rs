//! Test only allocator measurements scoped to the calling test thread.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Active allocation call count and requested bytes for this thread alone.
    static COUNTS: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
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

    /// Preserves the system allocator's zero initialization contract.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        // Safety: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc_zeroed(layout) }
    }

    /// Releases the original system allocation without counting a new request.
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // Safety: Both values are forwarded unchanged from the allocator caller.
        unsafe { System.dealloc(pointer, layout) }
    }

    /// Records the complete replacement request without changing reallocation semantics.
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        // Safety: All original arguments are forwarded unchanged.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

/// Clears a measurement even when the tested operation unwinds.
struct Measurement;

impl Drop for Measurement {
    /// Disables counting before subsequent test harness allocations.
    fn drop(&mut self) {
        COUNTS.with(|counts| counts.set(None));
    }
}

/// Returns the result, allocation request count and total requested bytes for one operation.
pub(super) fn measure<T>(operation: impl FnOnce() -> T) -> (T, usize, usize) {
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
