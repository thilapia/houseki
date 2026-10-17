//! Redacted failures to select a supported payment witness shape.

/// Unsupported borrowed witness counts without any private values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessShapeError {
    /// The number of input spends is outside the supported one or two input shapes.
    #[error("unsupported payment input count")]
    UnsupportedInputCount,

    /// The number of outputs is outside the supported one or two output shapes.
    #[error("unsupported payment output count")]
    UnsupportedOutputCount,
}
