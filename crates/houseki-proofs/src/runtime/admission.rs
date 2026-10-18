//! Scoped ownership of the shared proof operation slot.

use super::ProofRuntime;
use std::sync::atomic::Ordering;

/// Releases admission on success, failure or normal unwinding.
pub(crate) struct Admission<'a> {
    /// Runtime whose operation slot is currently held.
    pub(super) runtime: &'a ProofRuntime,
}

impl Drop for Admission<'_> {
    /// Makes the runtime available without retaining any operation inputs.
    fn drop(&mut self) {
        self.runtime.busy.store(false, Ordering::Release);
    }
}
