//! Portable identity bytes resolved before untrusted proof decoding.

use super::{IDENTITY_BYTES, Relation};
use houseki_types::ProofProfileId;

/// Expected identity selected by trusted configuration rather than decoded proof fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpectedIdentity {
    /// Immutable profile identifier required by the actual body.
    pub(crate) profile: ProofProfileId,

    /// Operation established by the selected family.
    pub(crate) relation: Relation,

    /// Actual count layout selected before decoding.
    pub(crate) shape: u32,

    /// Complete digest of the retained configuration and relation manifest.
    pub(crate) manifest: [u8; 64],
}

impl ExpectedIdentity {
    /// Writes the exact fixed identity without native width or alignment dependence.
    pub(crate) fn to_bytes(self) -> [u8; IDENTITY_BYTES] {
        let mut bytes = [0; IDENTITY_BYTES];
        bytes[..8].copy_from_slice(b"HKPROOF1");
        bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.profile.value().to_le_bytes());
        bytes[16..20].copy_from_slice(&(self.relation as u32).to_le_bytes());
        bytes[20..24].copy_from_slice(&self.shape.to_le_bytes());
        bytes[24..].copy_from_slice(&self.manifest);

        bytes
    }
}
