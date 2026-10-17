//! Nonblocking shared admission for one proof operation at a time.

mod admission;
mod error;

pub(crate) use admission::Admission;
pub use error::RuntimeError;

use std::sync::atomic::{AtomicBool, Ordering};

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

    /// Checks allocator integration without importing witnesses or admitting a proof profile.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Busy`] while another operation holds this runtime, then
    /// [`RuntimeError::BackendUnavailable`] if the allocator adapter is absent, backend parallelism
    /// is enabled or panic unwinding is disabled.
    ///
    /// A default consumer without a global [`crate::ProofAllocator`] fails this preflight.
    ///
    /// ```
    /// use houseki_proofs::{ProofRuntime, RuntimeError};
    /// let runtime = ProofRuntime::new();
    /// assert!(matches!(runtime.check_prover_allocator(), Err(RuntimeError::BackendUnavailable)));
    /// ```
    #[cfg(feature = "prover")]
    pub fn check_prover_allocator(&self) -> Result<(), RuntimeError> {
        let _admission = self.acquire()?;
        let token = crate::CancellationToken::new();
        crate::memory::Scope::enter(&token)
            .and_then(crate::memory::Scope::finish)
            .map_err(|_| RuntimeError::BackendUnavailable)?;

        Ok(())
    }

    /// Acquires the combined work slot without waiting for another request.
    #[cfg_attr(
        not(any(test, feature = "prover")),
        expect(dead_code, reason = "used by private proof execution")
    )]
    pub(crate) fn acquire(&self) -> Result<Admission<'_>, RuntimeError> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| RuntimeError::Busy)?;

        Ok(Admission { runtime: self })
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

    /// Requires the same admission slot for allocator preflight and recognizes the installed adapter.
    #[cfg(feature = "prover")]
    #[test]
    fn prover_allocator_preflight_respects_admission() {
        let runtime = ProofRuntime::new();
        runtime.check_prover_allocator().unwrap();

        let lease = runtime.acquire().unwrap();

        assert!(matches!(
            runtime.check_prover_allocator(),
            Err(RuntimeError::Busy)
        ));

        drop(lease);

        runtime.check_prover_allocator().unwrap();
    }

    /// Detects feature unification that would move private allocations outside the worker boundary.
    #[cfg(feature = "prover")]
    #[test]
    fn compiled_backend_mode_matches_preflight() {
        let result = ProofRuntime::new().check_prover_allocator();

        if p3_maybe_rayon::PARALLEL_ENABLED || !cfg!(panic = "unwind") {
            assert_eq!(result, Err(RuntimeError::BackendUnavailable));
        } else {
            assert_eq!(result, Ok(()));
        }
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
