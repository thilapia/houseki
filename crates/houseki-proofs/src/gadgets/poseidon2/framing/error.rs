//! Redacted failures from fixed hash layouts and their byte assignment.

/// Framing failures without private bytes, indices or intermediate values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FramingError {
    /// A public label, count, length or padded layout exceeds its representation.
    #[error("hash frame layout is too large")]
    LayoutTooLarge,

    /// A requested public block index falls outside the padded transcript.
    #[error("hash frame block index is out of bounds")]
    BlockIndexOutOfBounds,

    /// Input or destination lengths differ from the trusted circuit layout.
    #[error("hash frame storage does not match its layout")]
    ShapeMismatch,

    /// An input field value does not represent a byte.
    #[error("hash frame input is not a byte")]
    InvalidByte,
}
