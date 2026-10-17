//! Identifiers for proof configurations.

/// Identifies the proof configuration expected by a transaction or verifier.
///
/// The profile specifies proof system parameters and allowed relations for the verifier.
///
/// This identifier is separate from the protocol version and carries neither the configuration
/// nor a proof.
///
/// Every `u32` value is representable, including zero, but constructing an identifier does not
/// establish that the profile is supported or that a proof is valid.
///
/// The verifier must resolve an allowed profile under the active protocol rules and verify the
/// proof against the expected transaction statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProofProfileId(
    /// Numeric declared proof configuration identifier.
    u32,
);

impl ProofProfileId {
    /// Constructs a proof profile identifier without checking support.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric proof profile identifier.
    pub const fn value(&self) -> u32 {
        self.0
    }
}
