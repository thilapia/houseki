//! Value free marker for a cooperative cancellation unwind.

/// A typed cancellation unwind payload containing no witness values or backend diagnostics.
#[derive(Debug)]
pub(crate) struct Cancelled;
