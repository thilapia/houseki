//! Identifiers for recipient address formats.

/// Identifies the format used to interpret a recipient address.
///
/// The format determines how the address represents its recipient descriptor.
///
/// It is separate from the protocol version, note version and cryptographic suite, which
/// describe their own rules and can evolve independently.
///
/// Every `u32` value is representable, including zero, but constructing a value does not
/// establish support or address validity.
///
/// Address parsing must check support and validate the descriptor under the selected format
/// before the sender uses it to create an output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressFormatVersion(
    /// Numeric recipient descriptor format identifier.
    u32,
);

impl AddressFormatVersion {
    /// Constructs an address format version identifier without checking support.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric address format version identifier.
    pub const fn value(&self) -> u32 {
        self.0
    }
}
