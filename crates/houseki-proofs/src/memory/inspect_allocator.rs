//! Test allocator observing cleared bytes before forwarding release.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};

/// Records the observed bytes immediately before the underlying allocator releases them.
pub(super) static SAW_ZEROES: AtomicBool = AtomicBool::new(true);

/// Checks a fixed aligned fixture after the production allocator has cleared its payload.
pub(super) struct InspectAllocator;

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
