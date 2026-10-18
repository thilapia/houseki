//! Synthetic external acceptance policy kept distinct from mathematical proof verification.

use houseki_proofs::VerifiedPayment;
use houseki_types::{NoteTreeAnchor, Nullifier};
use std::collections::HashSet;

/// Local demonstration state for eligibility and replay checks without a ledger implementation.
pub(super) struct Policy {
    /// Independently selected eligible anchor for the next operation.
    pub(super) eligible: NoteTreeAnchor,

    /// Public markers already accepted by this synthetic policy.
    spent: HashSet<Nullifier>,
}

impl Policy {
    /// Starts with no accepted markers and an independently chosen anchor.
    pub(super) fn new(eligible: NoteTreeAnchor) -> Self {
        Self {
            eligible,
            spent: HashSet::new(),
        }
    }

    /// Checks external acceptance conditions on an already verified complete payment.
    pub(super) fn check(&self, evidence: &VerifiedPayment<'_>) -> Result<(), &'static str> {
        if evidence.anchor() != &self.eligible {
            return Err("ineligible anchor");
        }

        if evidence
            .body()
            .inputs()
            .nullifiers()
            .iter()
            .any(|marker| self.spent.contains(marker))
        {
            return Err("already spent input");
        }

        Ok(())
    }

    /// Records public markers only in this synthetic set after rechecking acceptance.
    ///
    /// A production consumer must combine these changes with append and every other effect atomically.
    pub(super) fn record(&mut self, evidence: &VerifiedPayment<'_>) -> Result<(), &'static str> {
        self.check(evidence)?;
        self.spent
            .extend(evidence.body().inputs().nullifiers().iter().copied());

        Ok(())
    }
}
