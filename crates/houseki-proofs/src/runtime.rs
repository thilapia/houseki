//! Nonblocking shared admission for one proof operation at a time.

use std::sync::atomic::{AtomicBool, Ordering};

/// Failure to acquire the shared runtime operation slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    /// Another proving or verification operation already owns this runtime.
    #[error("proof runtime is busy")]
    Busy,
}

/// Admits one operation without queuing or retaining callers' witnesses.
///
/// Applications sharing work across several runtime instances enforce their own aggregate limit.
#[derive(Debug, Default)]
pub struct ProofRuntime {
    /// Exclusive ownership state of the combined proving and verification slot.
    busy: AtomicBool,
}

impl ProofRuntime {
    /// Creates an idle runtime without allocating or acquiring entropy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquires the combined work slot without waiting for another request.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by private proof execution")
    )]
    pub(crate) fn acquire(&self) -> Result<Admission<'_>, RuntimeError> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| RuntimeError::Busy)?;
        Ok(Admission { runtime: self })
    }
}

/// Releases admission on success, failure or normal unwinding.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by private proof execution")
)]
pub(crate) struct Admission<'a> {
    /// Runtime whose operation slot is currently held.
    runtime: &'a ProofRuntime,
}

impl Drop for Admission<'_> {
    /// Makes the runtime available without retaining any operation inputs.
    fn drop(&mut self) {
        self.runtime.busy.store(false, Ordering::Release);
    }
}

/// Admission release and concurrent exclusion properties.
#[cfg(test)]
mod tests {
    use super::*;

    /// Shares the slot between operation kinds and releases it on every scoped exit.
    #[test]
    fn busy_runtime_rejects_without_queuing_and_releases_its_lease() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        assert!(matches!(runtime.acquire(), Err(RuntimeError::Busy)));
        std::thread::scope(|scope| {
            scope.spawn(|| assert!(matches!(runtime.acquire(), Err(RuntimeError::Busy))));
        });
        drop(lease);
        assert!(runtime.acquire().is_ok());
    }

    /// Returns the slot during unwinding without storing any caller request.
    #[test]
    fn unwinding_releases_admission() {
        let runtime = ProofRuntime::new();
        let result = std::panic::catch_unwind(|| {
            let _lease = runtime.acquire().unwrap();
            panic!("synthetic operation failure");
        });
        assert!(result.is_err());
        assert!(runtime.acquire().is_ok());
    }
}
