//! Borrowed transcript positions without an owned private byte buffer.

/// One public framing byte or borrowed field byte from an input part.
pub(super) enum Byte<'a, V> {
    /// A fixed label or integer-prefix byte selected by the layout.
    Constant(u8),

    /// An input cell whose byte range is established by the framing constraints.
    Input(&'a V),
}
