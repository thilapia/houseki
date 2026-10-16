use thiserror::Error;

/// Failure to represent or complete a cryptographic transcript frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CryptoFramingError {
    /// The complete layout would contain more than `u32::MAX` parts.
    #[error("cryptographic frame contains too many parts")]
    TooManyParts,

    /// A part's byte length cannot be represented as a `u64`.
    #[error("cryptographic frame part is too long")]
    PartTooLong,

    /// The complete framed byte length cannot be represented as a `u64`.
    #[error("cryptographic frame is too long for its length prefix")]
    FrameTooLong,

    /// The encoder emitted a different number of parts than it declared.
    #[error("cryptographic frame part count does not match its declaration")]
    PartCountMismatch,
}
