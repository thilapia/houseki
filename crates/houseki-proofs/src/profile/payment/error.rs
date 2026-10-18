//! Failures to select one supported payment shape.

/// Invalid public counts without retained transaction values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ShapeError {
    /// The input count is outside one through four.
    #[error("unsupported payment input count")]
    UnsupportedInputCount,

    /// The output count is outside one through two.
    #[error("unsupported payment output count")]
    UnsupportedOutputCount,
}
