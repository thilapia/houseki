//! Shared accounting retained by every allocation belonging to an attempt.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

/// Public counters and cancellation state retained until the last tagged allocation is released.
pub(super) struct Account {
    /// Number of currently live tagged allocations.
    pub(super) live: AtomicUsize,

    /// Number of successful tagged allocation requests.
    pub(super) allocations: AtomicUsize,

    /// Currently allocated payload bytes, excluding allocator headers.
    pub(super) bytes: AtomicUsize,

    /// Maximum simultaneously retained payload bytes.
    pub(super) peak: AtomicUsize,

    /// Total payload bytes cleared before release.
    pub(super) wiped: AtomicUsize,

    /// Shared monotonic cancellation request for this attempt.
    pub(super) cancelled: Arc<AtomicBool>,
}

impl Account {
    /// Records a successful request without allocating or panicking inside the allocator.
    pub(super) fn allocated(&self, size: usize) {
        self.live.fetch_add(1, Ordering::Relaxed);
        self.allocations.fetch_add(1, Ordering::Relaxed);

        let bytes = self
            .bytes
            .fetch_add(size, Ordering::Relaxed)
            .saturating_add(size);
        self.peak.fetch_max(bytes, Ordering::Relaxed);
    }

    /// Records cleanup only after volatile stores have cleared the complete payload.
    pub(super) fn released(&self, size: usize) {
        self.wiped.fetch_add(size, Ordering::Relaxed);
        self.bytes.fetch_sub(size, Ordering::Relaxed);
        self.live.fetch_sub(1, Ordering::Release);
    }
}
