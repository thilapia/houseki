//! Fixed checkpoint rules derived without wall clock input.

use super::{ExecutionPolicy, PolicyError};
use houseki_types::CheckpointSequence;
use std::ops::RangeInclusive;

/// Immutable policy and sequence used for one checkpoint's state decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRules {
    /// Checked successor of the parent checkpoint sequence.
    sequence: CheckpointSequence,

    /// Policy fixed before any occurrence changes working state.
    policy: ExecutionPolicy,

    /// Eligible descriptors frozen before any occurrence changes working state.
    eligible_anchors: Vec<houseki_types::NoteTreeAnchor>,
}

impl CheckpointRules {
    /// Borrows the complete immutable eligible descriptor view for this checkpoint.
    pub fn eligible_anchors(&self) -> &[houseki_types::NoteTreeAnchor] {
        &self.eligible_anchors
    }

    /// Fixes policy from actual logical state before deriving the next checkpoint rules.
    ///
    /// # Errors
    ///
    /// Preserves policy validation and exhausted-sequence failures.
    pub fn derive(
        state: &crate::LogicalState,
        parent_sequence: CheckpointSequence,
    ) -> Result<Self, PolicyError> {
        let mut rules = Self::next(state.policy(), parent_sequence)?;
        rules
            .eligible_anchors
            .try_reserve_exact(state.anchors().len())
            .map_err(|_| PolicyError::Allocation)?;
        for record in state.anchors() {
            if rules
                .eligible_sequences()
                .contains(&record.sequence().value())
            {
                rules.eligible_anchors.push(record.anchor());
            }
        }
        Ok(rules)
    }

    /// Derives the next sequence and fixes its policy without authenticating parent state.
    ///
    /// # Errors
    ///
    /// Rejects invalid anchor retention or an exhausted parent counter.
    pub fn next(policy: &ExecutionPolicy, parent: CheckpointSequence) -> Result<Self, PolicyError> {
        policy.validate()?;
        let sequence = parent
            .checked_next()
            .ok_or(PolicyError::SequenceExhausted)?;
        Ok(Self {
            sequence,
            policy: policy.clone(),
            eligible_anchors: Vec::new(),
        })
    }

    /// Returns the checkpoint being evaluated.
    pub const fn sequence(&self) -> CheckpointSequence {
        self.sequence
    }

    /// Borrows the fixed execution policy.
    pub const fn policy(&self) -> &ExecutionPolicy {
        &self.policy
    }

    /// Checks a complete descriptor against the immutable eligible history view.
    pub(crate) fn allows_anchor(&self, anchor: houseki_types::NoteTreeAnchor) -> bool {
        self.eligible_anchors.contains(&anchor)
    }

    /// Returns the inclusive historical sequence window, excluding this checkpoint.
    pub fn eligible_sequences(&self) -> RangeInclusive<u64> {
        let end = self.sequence.value() - 1;
        let start = self
            .sequence
            .value()
            .saturating_sub(self.policy.limits().anchor_window());
        start..=end
    }
}

/// Inclusive checkpoint window edges.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::manifest;

    /// Prevents off by one errors at genesis, full window and retained-history boundaries.
    #[test]
    fn eligible_window_is_inclusive() {
        let candidate = manifest().candidate().unwrap();
        for (next, first, last) in [(1, 0, 0), (32, 0, 31), (33, 1, 32), (65, 33, 64)] {
            let rules =
                CheckpointRules::derive(candidate.state(), CheckpointSequence::new(next - 1))
                    .unwrap();
            assert_eq!(rules.eligible_sequences(), first..=last);
        }
    }
}
