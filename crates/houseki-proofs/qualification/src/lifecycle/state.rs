//! Serialized foreground admission without a pending request queue.

use houseki_proofs::CancellationToken;
use std::sync::Arc;

/// Only public lifecycle state and the active attempt's monotonic cancellation token.
#[derive(Default)]
pub(super) struct State {
    /// Whether callbacks currently permit new work.
    pub(super) foreground: bool,

    /// Identifier allocated to the most recent admitted attempt.
    pub(super) generation: u64,

    /// Token retained until the worker's lease drops after private cleanup.
    pub(super) active: Option<Arc<CancellationToken>>,
}
