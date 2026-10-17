//! Trusted operation identities independent of untrusted proof headers.

mod identity;
mod relation;
pub(crate) mod reward_withdrawal;

pub(crate) use identity::ExpectedIdentity;
pub(crate) use relation::Relation;

use houseki_types::{BodyCodecLimits, PaymentCountLimits};

/// Complete identity bytes preceding the payload length.
pub(crate) const IDENTITY_BYTES: usize = 88;

/// Inclusive bound on the complete encoded proof.
pub(crate) const MAX_PROOF_BYTES: usize = 2_097_152;

/// Shared representation bounds applied before body encoding or statement allocation.
pub(crate) fn body_limits() -> BodyCodecLimits {
    BodyCodecLimits::new(
        PaymentCountLimits::new(2, 2).expect("nonzero fixed counts"),
        4096,
        16384,
    )
}
