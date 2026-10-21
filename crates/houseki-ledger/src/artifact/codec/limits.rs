//! Explicit bounds for untrusted canonical record decoding.

/// Reference decoding limits independent of a caller's source validity claim.
#[derive(Debug, Clone, Copy)]
pub struct DecodeLimits {
    /// Maximum complete input bytes checked before parsing.
    pub max_bytes: usize,

    /// Maximum record elements and decoded collection allocation in one list.
    pub max_records: usize,
}

impl DecodeLimits {
    /// Returns bounded reference decoding limits, including the largest complete source unit.
    pub const fn reference() -> Self {
        Self {
            max_bytes: 67_108_864,
            max_records: 8256,
        }
    }
}
