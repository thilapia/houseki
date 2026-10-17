//! Identifiers for note formats and rules.

/// Identifies the format and rules used by a note.
///
/// The version determines how the note is interpreted, including its commitment and nullifier
/// rules.
///
/// It is separate from the protocol version and proof profile used by a transaction that creates
/// or spends the note.
///
/// Every `u32` value is representable, including zero, but constructing a value does not
/// establish support or note validity.
///
/// Recovery and verification must check support and apply the rules associated with the note's
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoteVersion(
    /// Numeric immutable note format and rule identifier.
    u32,
);

impl NoteVersion {
    /// Constructs a note version identifier without checking support.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric note version identifier.
    pub const fn value(&self) -> u32 {
        self.0
    }
}
