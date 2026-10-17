//! Value independent assignment failures for sponge trace geometry.

/// Rejects incompatible caller supplied buffers before assignment writes any cells.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SpongeError {
    /// Input must contain at least one padded block and one extra squeeze permutation.
    #[error("sponge trace shape does not match the padded blocks")]
    ShapeMismatch,
}
