//! Redacted failures from complete spend assignment.

/// Invalid storage or byte sources without private diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SpendError {
    /// Destination cannot contain every strided operation row.
    #[error("spend storage does not match its layout")]
    ShapeMismatch,

    /// An assignment source is outside the canonical byte range.
    #[error("spend input is not a byte")]
    InvalidByte,
}
