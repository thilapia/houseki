//! Public transcript positions without an owned private byte buffer.

/// One fixed framing byte or public coordinate within an input part.
#[derive(Clone, Copy)]
pub(super) enum Byte {
    /// A fixed label or integer-prefix byte selected by the layout.
    Constant(u8),

    /// An input coordinate whose value is supplied and constrained by its consumer.
    Input {
        /// Index of the ordered transcript part.
        part: usize,

        /// Byte offset within that part.
        offset: usize,
    },
}
