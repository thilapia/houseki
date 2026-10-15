//! Identifiers for cryptographic suites.

/// Identifies the cryptographic suite used by an address or encrypted note.
///
/// A suite specifies a complete profile for key establishment, key derivation
/// and authenticated encryption, including their parameters and context rules.
/// Its identifier is separate from address and note versions and does not
/// allow individual algorithms to be selected independently.
///
/// Every `u32` value is representable, including zero, but constructing an
/// identifier does not establish support or validate cryptographic material.
/// Senders and recipients must resolve an allowed suite for the relevant
/// context and apply its validation rules before using that material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CryptoSuiteId(u32);

impl CryptoSuiteId {
    /// Constructs a cryptographic suite identifier without checking support.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric cryptographic suite identifier.
    pub const fn value(&self) -> u32 {
        self.0
    }
}
