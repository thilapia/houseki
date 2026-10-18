//! Failures to resolve trusted payment geometry.

/// An internal schedule cannot fit the retained bounded family geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PaymentLayoutError {
    /// Trace dimensions exceed the checked family envelope.
    #[error("unsupported payment geometry")]
    InvalidGeometry,
}
