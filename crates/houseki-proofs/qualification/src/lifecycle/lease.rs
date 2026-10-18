//! Worker admission retained until all operation owners have been destroyed.

use super::Controller;
use houseki_proofs::CancellationToken;
use std::sync::Arc;

/// A single attempt's public identity and fresh cancellation token.
pub struct Lease {
    /// Shared controller whose admission is released last.
    pub(super) controller: Arc<Controller>,

    /// Cancellation observed by this attempt only.
    pub(super) token: Arc<CancellationToken>,

    /// Monotonically increasing public attempt identity.
    pub(super) generation: u64,
}

impl Lease {
    /// Borrows the unique attempt token without permitting reset or reuse.
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    /// Identifies the attempt without exposing any witness or entropy.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for Lease {
    /// Returns admission after caller scopes have finished destroying protected work.
    fn drop(&mut self) {
        let mut state = self
            .controller
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.generation == self.generation {
            state.active = None;
        }
    }
}
