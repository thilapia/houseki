//! Scoped cleanup for thread local allocation observations.

use super::COUNTS;

/// Clears a measurement even when the tested operation unwinds.
pub(super) struct Measurement;

impl Drop for Measurement {
    /// Disables counting before subsequent test harness allocations.
    fn drop(&mut self) {
        COUNTS.with(|counts| counts.set(None));
    }
}
