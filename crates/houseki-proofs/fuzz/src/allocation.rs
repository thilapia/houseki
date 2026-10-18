//! Allocation observations for each call around the actual public verifier.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

/// System allocator with thread local live byte and request observations.
pub(crate) struct ObservedAllocator;

thread_local! {
    /// Whether the current call belongs to the observed verifier scope.
    static ACTIVE: Cell<bool> = const { Cell::new(false) };

    /// Currently live requested bytes allocated inside the observation.
    static LIVE: Cell<usize> = const { Cell::new(0) };

    /// Largest simultaneous live request total inside the observation.
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for ObservedAllocator {
    /// Records successful requests using the same system allocation contract.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && ACTIVE.try_with(Cell::get).unwrap_or(false) {
            LIVE.with(|live| {
                live.set(live.get() + layout.size());
                PEAK.with(|peak| peak.set(peak.get().max(live.get())));
            });
        }

        pointer
    }

    /// Accounts for releases before returning ownership to the system allocator.
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if ACTIVE.try_with(Cell::get).unwrap_or(false) {
            LIVE.with(|live| live.set(live.get().saturating_sub(layout.size())));
        }

        unsafe { System.dealloc(pointer, layout) };
    }
}

/// Observes one normal verifier return and requires its temporary allocations to be released.
///
/// Panics remain process failures rather than successful fuzz outcomes.
pub(crate) fn measure<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    LIVE.with(|live| live.set(0));
    PEAK.with(|peak| peak.set(0));
    ACTIVE.with(|active| assert!(!active.replace(true)));
    let result = operation();
    ACTIVE.with(|active| active.set(false));
    assert_eq!(
        LIVE.with(Cell::get),
        0,
        "verifier retained observed allocations"
    );

    (result, PEAK.with(Cell::get))
}

/// Observations distinguish transient live allocation from total requested bytes.
#[cfg(test)]
mod tests {
    use super::*;

    /// A real allocated buffer is counted and released within the observed scope.
    #[test]
    fn observes_real_allocation_and_release() {
        let (length, peak) = measure(|| {
            let bytes = std::hint::black_box(vec![7_u8; 8192]);
            std::hint::black_box(bytes.len())
        });

        assert_eq!(length, 8192);
        assert!(peak >= 8192);
    }
}
