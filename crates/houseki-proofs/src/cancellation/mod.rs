//! Monotonic cancellation shared with one proving attempt.

mod attempt;

pub(crate) use attempt::Attempt;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A cancellation request that cannot be reset or reused for another attempt.
///
/// Share the token by reference or through `Arc` when a lifecycle callback must cancel a worker.
///
/// Cancellation is cooperative and does not promise destructor execution after process termination.
#[derive(Debug, Default)]
pub struct CancellationToken {
    /// Shared public cancellation state observed at backend checkpoints.
    pub(crate) cancelled: Arc<AtomicBool>,

    /// Whether any attempt has already claimed this token.
    claimed: AtomicBool,
}

impl CancellationToken {
    /// Creates a fresh uncancelled token for one attempt.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation permanently without waiting for worker cleanup.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Reports the request state without claiming that worker cleanup has finished.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Claims the token once, including attempts that fail before backend work begins.
    pub(crate) fn claim(&self) -> bool {
        !self.claimed.swap(true, Ordering::AcqRel) && !self.is_cancelled()
    }
}
