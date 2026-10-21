//! Temporary borrows from an owned whole unit authorization.

use houseki_proofs::ProofContext;
use houseki_types::{NoteTreeAnchor, Occurrence};

/// One occurrence whose complete containing unit already passed local authorization.
pub(crate) struct AuthorizedOccurrence<'a> {
    /// Exact original immutable occurrence and complete envelope bytes.
    pub(super) occurrence: &'a Occurrence,

    /// Registry recognized expected context retained by the unit owner.
    pub(super) context: &'a ProofContext,

    /// Independently trusted payment descriptor, absent for withdrawal.
    pub(super) anchor: Option<NoteTreeAnchor>,
}

impl<'a> AuthorizedOccurrence<'a> {
    /// Borrows the exact checked source occurrence.
    pub(crate) fn occurrence(&self) -> &'a Occurrence {
        self.occurrence
    }

    /// Borrows its exact recognized expected context.
    pub(crate) fn context(&self) -> &'a ProofContext {
        self.context
    }

    /// Returns its independently trusted payment anchor.
    pub(crate) const fn anchor(&self) -> Option<NoteTreeAnchor> {
        self.anchor
    }

    /// Supplies synthetic evidence only within private state transition tests.
    #[cfg(all(test, feature = "experimental-profiles"))]
    pub(crate) fn for_test(
        occurrence: &'a Occurrence,
        context: &'a ProofContext,
        anchor: Option<NoteTreeAnchor>,
    ) -> Self {
        Self {
            occurrence,
            context,
            anchor,
        }
    }
}
