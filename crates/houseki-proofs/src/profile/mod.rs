//! Trusted operation identities independent of untrusted proof headers.

use houseki_types::{BodyCodecLimits, PaymentCountLimits, ProofProfileId};

/// Complete identity bytes preceding the payload length.
pub(crate) const IDENTITY_BYTES: usize = 88;

/// Inclusive bound on the complete encoded proof.
pub(crate) const MAX_PROOF_BYTES: usize = 2_097_152;

/// Supported operation names without an assertion that a profile is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum Relation {
    /// Knowledge of a complete payment's linked spends and outputs.
    Payment = 1,

    /// Knowledge of the single withdrawal output opening.
    RewardWithdrawal = 2,
}

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

/// Shared representation bounds applied before body encoding or statement allocation.
pub(crate) fn body_limits() -> BodyCodecLimits {
    BodyCodecLimits::new(
        PaymentCountLimits::new(2, 2).expect("nonzero fixed counts"),
        4096,
        16384,
    )
}
