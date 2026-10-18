//! Foreground worker ownership shared by native application lifecycle callbacks.

mod error;
mod lease;
mod state;

pub use error::LifecycleError;
pub use lease::Lease;

use houseki_proofs::CancellationToken;
use state::State;
use std::sync::{Arc, Mutex};

/// Owns one combined operation slot and never queues a request or stores a private fixture.
#[derive(Default)]
pub struct Controller {
    /// Public admission state, with no protected owner or checkpoint.
    state: Mutex<State>,
}

impl Controller {
    /// Creates a background controller that admits no work until explicitly resumed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates lifecycle state and permanently cancels any attempt on background notification.
    ///
    /// Returning does not claim that the worker has finished cleanup or will run while suspended.
    ///
    /// # Errors
    ///
    /// Rejects poisoned state rather than admitting work after a callback panic.
    pub fn set_foreground(&self, foreground: bool) -> Result<(), LifecycleError> {
        let mut state = self.state.lock().map_err(|_| LifecycleError::Poisoned)?;
        state.foreground = foreground;
        if !foreground && let Some(token) = &state.active {
            token.cancel();
        }

        Ok(())
    }

    /// Admits one fresh attempt without waiting or retaining any pending request.
    ///
    /// # Errors
    ///
    /// Returns background or busy state before allocating a token.
    pub fn enter(self: &Arc<Self>) -> Result<Lease, LifecycleError> {
        let mut state = self.state.lock().map_err(|_| LifecycleError::Poisoned)?;
        if !state.foreground {
            return Err(LifecycleError::Background);
        }

        if state.active.is_some() {
            return Err(LifecycleError::Busy);
        }

        let generation = state
            .generation
            .checked_add(1)
            .ok_or(LifecycleError::Exhausted)?;
        let token = Arc::new(CancellationToken::new());
        state.generation = generation;
        state.active = Some(Arc::clone(&token));

        Ok(Lease {
            controller: Arc::clone(self),
            token,
            generation,
        })
    }
}

/// Cancellation monotonicity and admission while a previous worker is still cleaning up.
#[cfg(test)]
mod tests {
    use super::*;

    /// Resumption cannot reuse the old token or overlap the interrupted attempt.
    #[test]
    fn background_cancel_requires_cleanup_before_a_fresh_attempt() {
        let controller = Arc::new(Controller::new());
        assert!(matches!(
            controller.enter(),
            Err(LifecycleError::Background)
        ));
        controller.set_foreground(true).unwrap();
        let first = controller.enter().unwrap();
        let first_token = Arc::clone(&first.token);
        let first_generation = first.generation();
        assert!(!first.token().is_cancelled());
        assert!(matches!(controller.enter(), Err(LifecycleError::Busy)));
        controller.set_foreground(false).unwrap();
        assert!(first.token().is_cancelled());
        controller.set_foreground(true).unwrap();
        assert!(matches!(controller.enter(), Err(LifecycleError::Busy)));
        drop(first);

        let second = controller.enter().unwrap();
        assert!(second.generation() > first_generation);
        assert!(!second.token().is_cancelled());
        assert!(!Arc::ptr_eq(&first_token, &second.token));
        assert!(first_token.is_cancelled());
    }

    /// Another callback cannot acquire a lease concurrently, even after cancellation is requested.
    #[test]
    fn concurrent_requests_never_queue_or_overlap() {
        let controller = Arc::new(Controller::new());
        controller.set_foreground(true).unwrap();
        let active = controller.enter().unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| assert!(matches!(controller.enter(), Err(LifecycleError::Busy))));
            }
        });

        drop(active);

        assert!(controller.enter().is_ok());
    }
}
