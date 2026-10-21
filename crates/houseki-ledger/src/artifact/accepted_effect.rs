//! Public representation of the canonical accepted effect record.

use crate::{AccountEffect, NoteAppend};
use houseki_types::{Amount, Nullifier};

/// Unverified accepted effect fields with no publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedEffect {
    /// Inserted markers in input order.
    pub nullifiers: Vec<Nullifier>,

    /// New leaves in original output order.
    pub appends: Vec<NoteAppend>,

    /// Coalesced changed accounts sorted by complete identity.
    pub accounts: Vec<AccountEffect>,

    /// Pool before the occurrence.
    pub before_pool: Amount,

    /// Pool after the occurrence.
    pub after_pool: Amount,
}
