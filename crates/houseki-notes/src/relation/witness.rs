//! Borrowed protected inputs shared by native spend and payment checks.

use crate::NoteOpening;
use houseki_crypto::{NullifierKey, SpendingKey};
use houseki_state::NoteMembershipWitness;
use std::fmt;

/// Borrowed private inputs for a concrete native spend relation.
///
/// Construction establishes no equation and leaves all original protected owners with the caller.
///
/// No key, amount or path is copied into an unprotected owned representation.
pub struct SpendWitness<'a> {
    /// Original positive opening whose commitment must have actual membership.
    pub(super) opening: &'a NoteOpening,

    /// Original spending capability linked to the declared ownership.
    pub(super) spending_key: &'a SpendingKey,

    /// Original nullifier capability shared by ownership and spend marker derivation.
    pub(super) nullifier_key: &'a NullifierKey,

    /// Owned protected path retaining the same original position used by the nullifier.
    pub(super) membership: &'a NoteMembershipWitness,
}

impl<'a> SpendWitness<'a> {
    /// Borrows the original protected relation inputs without validating their correspondence.
    pub const fn new(
        opening: &'a NoteOpening,
        spending_key: &'a SpendingKey,
        nullifier_key: &'a NullifierKey,
        membership: &'a NoteMembershipWitness,
    ) -> Self {
        Self {
            opening,
            spending_key,
            nullifier_key,
            membership,
        }
    }

    /// Borrows the original protected opening without extending its lifetime or copying it.
    #[cfg(feature = "proofs")]
    pub const fn opening(&self) -> &'a NoteOpening {
        self.opening
    }

    /// Borrows the original protected spending key without extending its lifetime or copying it.
    #[cfg(feature = "proofs")]
    pub const fn spending_key(&self) -> &'a SpendingKey {
        self.spending_key
    }

    /// Borrows the original protected nullifier key without extending its lifetime or copying it.
    #[cfg(feature = "proofs")]
    pub const fn nullifier_key(&self) -> &'a NullifierKey {
        self.nullifier_key
    }

    /// Borrows the original protected membership witness without extending its lifetime or copying it.
    #[cfg(feature = "proofs")]
    pub const fn membership(&self) -> &'a NoteMembershipWitness {
        self.membership
    }
}

impl fmt::Debug for SpendWitness<'_> {
    /// Writes a fixed label without formatting any referenced private material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SpendWitness([REDACTED])")
    }
}
