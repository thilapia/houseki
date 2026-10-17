//! Failures to derive a bounded statement from native transaction data.

use houseki_types::BodyCodecError;

/// Failure to derive a bounded statement from the actual body and expected metadata.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StatementError {
    /// Some declared context component differs from the caller's expected value.
    #[error("transaction context mismatch")]
    ContextMismatch,

    /// The actual input or output count has no supported layout.
    #[error("unsupported payment shape")]
    UnsupportedShape,

    /// The expected anchor network or root differs from the body.
    #[error("note anchor mismatch")]
    AnchorMismatch,

    /// An empty anchor cannot contain a spent note.
    #[error("empty note anchor")]
    EmptyAnchor,

    /// Two public input markers are equal.
    #[error("duplicate payment nullifier")]
    DuplicateNullifier,

    /// The trusted identity does not describe this body's profile, family or shape.
    #[error("proof identity mismatch")]
    IdentityMismatch,

    /// The native body violates the selected representation bounds.
    #[error(transparent)]
    InvalidBody(
        /// Original bounded native body encoding failure.
        #[from]
        BodyCodecError,
    ),
}
