//! Identifiers for protocol rule versions.

/// Identifies the protocol rules expected by a transaction or execution context.
///
/// A protocol version is separate from a node software release, note format or
/// proof profile. Keeping it in its own type prevents those identifiers from
/// being used interchangeably.
///
/// Every `u32` value is representable, including zero, but constructing a value
/// does not establish that its version is supported or active. Execution must
/// check it against the protocol rules selected for the current checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    /// Constructs a protocol version identifier without checking support.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric protocol version identifier.
    pub const fn value(&self) -> u32 {
        self.0
    }
}
