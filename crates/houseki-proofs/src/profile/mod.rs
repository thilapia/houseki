//! Trusted operation identities independent of untrusted proof headers.

mod identity;
pub(crate) mod payment;
mod registered;
mod relation;
pub(crate) mod reward_withdrawal;

pub(crate) use identity::ExpectedIdentity;
pub(crate) use registered::RegisteredProfile;
pub(crate) use relation::Relation;

/// Complete identity bytes preceding the payload length.
pub(crate) const IDENTITY_BYTES: usize = 88;

/// Inclusive bound on the complete encoded proof.
pub(crate) const MAX_PROOF_BYTES: usize = 2_097_152;
