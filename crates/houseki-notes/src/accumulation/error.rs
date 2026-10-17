//! Failures to retain exact guarded amount totals.

use thiserror::Error;

/// A failure to retain an exact total within the private integer capacity.
#[derive(Debug, Error)]
pub(crate) enum AmountTotalError {
    /// Addition would exceed the full width sum without producing a usable replacement.
    #[error("amount total overflow")]
    Overflow,
}
