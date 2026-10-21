//! Complete reference unit identity representation.

/// Distinct 64 byte unit identifier without a derivation or trust claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixtureUnitId(
    /// Complete digest bytes.
    [u8; 64],
);

impl FixtureUnitId {
    /// Retains complete declared bytes without authenticating their derivation.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrows the complete digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Returns the complete digest bytes.
    pub const fn into_bytes(self) -> [u8; 64] {
        self.0
    }
}
