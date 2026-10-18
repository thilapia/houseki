//! Redacted occupied membership assignment failures.

/// Invalid storage or relation inputs without retained private values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MembershipError {
    /// Destination cannot contain every strided operation row.
    #[error("membership storage does not match its layout")]
    ShapeMismatch,

    /// An input field cell is not a byte.
    #[error("membership input is not a byte")]
    InvalidByte,

    /// Count exceeds the fixed depth-64 capacity.
    #[error("membership count exceeds tree capacity")]
    InvalidCount,

    /// Original position is not strictly below the occupied count.
    #[error("membership position is unoccupied")]
    UnoccupiedPosition,
}
