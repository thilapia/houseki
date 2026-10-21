//! Owned successful whole unit authorization without runtime leases or self references.

use super::{
    compatibility::Compatibility, dependencies::UnitDependencies, occurrence::AuthorizedOccurrence,
};
use crate::{ParentSnapshot, UnitPreparationError, VerifiedOrderUnit};

/// Exact immutable source inputs authorized only after every complete envelope succeeds.
///
/// There is no public unchecked constructor, mutable accessor or deserialization path.
///
/// ```compile_fail
/// use houseki_ledger::AuthorizedUnit;
/// let forged = AuthorizedUnit {};
/// ```
#[derive(Debug)]
pub struct AuthorizedUnit {
    /// Complete fixture order owner, including all proof and signature bytes.
    order: VerifiedOrderUnit,

    /// Frozen recognition dependencies and original compatibility interpretation.
    dependencies: UnitDependencies,
}

impl AuthorizedUnit {
    /// Seals the locally checked immutable owner only inside the validating component.
    pub(super) fn checked(order: VerifiedOrderUnit, dependencies: UnitDependencies) -> Self {
        Self {
            order,
            dependencies,
        }
    }

    /// Borrows complete immutable source inputs without allowing authorization
    /// replacement.
    pub const fn order_unit(&self) -> &VerifiedOrderUnit {
        &self.order
    }

    /// Iterates independently authenticated payment descriptors retained for later
    /// slices/replay.
    pub(crate) fn trusted_anchors(
        &self,
    ) -> impl Iterator<Item = houseki_types::NoteTreeAnchor> + '_ {
        self.dependencies.anchors.iter().flatten().copied()
    }

    /// Requires exactly the same immutable interpretation across slices or later parent
    /// states.
    pub(crate) fn require_compatible(
        &self,
        parent: &ParentSnapshot,
    ) -> Result<(), UnitPreparationError> {
        if self.dependencies.compatibility != Compatibility::capture(parent)? {
            return Err(UnitPreparationError::Integrity);
        }

        Ok(())
    }

    /// Borrows one checked occurrence without escaping references into a different
    /// owner.
    pub(crate) fn occurrence(&self, index: usize) -> Option<AuthorizedOccurrence<'_>> {
        Some(AuthorizedOccurrence {
            occurrence: self.order.occurrences().get(index)?,
            context: self.dependencies.contexts.get(index)?,
            anchor: *self.dependencies.anchors.get(index)?,
        })
    }
}
