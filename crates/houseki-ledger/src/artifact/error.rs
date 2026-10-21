//! Canonical record representation and local storage errors.

/// A reference record cannot be encoded or decoded under the explicit schema.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// A declared length, integer conversion or record count exceeds a decoding bound.
    #[error("artifact bound exceeded")]
    Bound,

    /// Input ends before its complete declared representation.
    #[error("truncated artifact record")]
    Truncated,

    /// A record has trailing bytes, unknown tags or inconsistent canonical contents.
    #[error("noncanonical artifact record")]
    Invalid,

    /// A bounded output or decoded collection could not reserve local memory.
    #[error("artifact allocation failed")]
    Allocation,

    /// An embedded native transaction body failed its existing codec.
    #[error(transparent)]
    Body(
        /// Original body failure retained as the source.
        #[from]
        houseki_types::BodyCodecError,
    ),

    /// A decoded policy failed its invariants.
    #[error(transparent)]
    Policy(
        /// Original policy failure retained as the source.
        #[from]
        crate::PolicyError,
    ),
}
