//! Disposable working state owns every mutable ledger component.

use super::{LogicalState, StateError};
use houseki_state::NoteTree;
use houseki_types::{NoteCommitment, NotePosition};
use std::collections::HashMap;
use std::sync::Arc;

/// Independently reconstructed state that has no publication authority.
pub struct WorkingState {
    /// Mutable state discarded in full on a local preparation failure.
    pub(crate) state: LogicalState,

    /// A local application error makes continued use invalid.
    pub(crate) poisoned: bool,
}

impl WorkingState {
    /// Rebuilds the concrete tree and copies mutable maps under the parent's policy
    /// bounds.
    ///
    /// # Errors
    ///
    /// Rejects capacity or conservation failures before reconstructing, then preserves
    /// local allocation, tree and integrity failures without mutating the parent.
    pub fn reconstruct(state: &LogicalState) -> Result<Self, StateError> {
        let limits = state.policy.limits();
        if state.leaves.len() as u128 > u128::from(limits.note_leaves())
            || state.spent.len() as u128 > u128::from(limits.spent_markers())
            || state.accounts.len() as u128 > u128::from(limits.accounts())
        {
            return Err(StateError::Capacity);
        }

        state.validate_conservation()?;
        let mut tree = NoteTree::new(state.network)?;
        let mut leaves = Vec::new();
        leaves
            .try_reserve_exact(state.leaves.len())
            .map_err(|_| StateError::Allocation)?;
        for &leaf in &state.leaves {
            tree.append(leaf)?;
            leaves.push(leaf);
        }

        if tree.anchor() != state.tree.anchor() {
            return Err(StateError::Integrity);
        }

        let mut spent = HashMap::new();
        spent
            .try_reserve(state.spent.len())
            .map_err(|_| StateError::Allocation)?;
        for (&key, &value) in &state.spent {
            if &key != value.as_bytes() {
                return Err(StateError::Integrity);
            }

            spent.insert(key, value);
        }

        let mut accounts = HashMap::new();
        accounts
            .try_reserve(state.accounts.len())
            .map_err(|_| StateError::Allocation)?;
        accounts.extend(
            state
                .accounts
                .iter()
                .map(|(&key, value)| (key, value.clone())),
        );

        let mut anchors = Vec::new();
        anchors
            .try_reserve_exact(state.anchors.len())
            .map_err(|_| StateError::Allocation)?;
        anchors.extend_from_slice(&state.anchors);

        Ok(Self {
            poisoned: false,
            state: LogicalState {
                network: state.network,
                tree,
                leaves,
                spent,
                accounts,
                anchors,
                policy: Arc::clone(&state.policy),
                committee_context: state.committee_context,
                committee: Arc::clone(&state.committee),
                pool: state.pool,
                issued: state.issued,
            },
        })
    }

    /// Borrows the current disposable state.
    pub const fn state(&self) -> &LogicalState {
        &self.state
    }

    /// Reports whether a local application failure has invalidated this disposable
    /// state.
    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Checks the working state's accounting invariant.
    pub fn validate_conservation(&self) -> Result<(), StateError> {
        self.state.validate_conservation()
    }

    /// Appends a checked note to disposable state, preserving repeated commitments.
    ///
    /// # Errors
    ///
    /// Checks reference capacity and storage before tree mutation and preserves tree
    /// failures.
    pub(crate) fn append(
        &mut self,
        commitment: NoteCommitment,
    ) -> Result<NotePosition, StateError> {
        if self.state.leaves.len() as u128 >= u128::from(self.state.policy.limits().note_leaves()) {
            return Err(StateError::Capacity);
        }

        self.state
            .leaves
            .try_reserve(1)
            .map_err(|_| StateError::Allocation)?;
        let position = self
            .state
            .tree
            .append(commitment)
            .map_err(|error| match error {
                houseki_state::NoteTreeError::Full => StateError::Integrity,
                error => StateError::Tree(error),
            })?;

        self.state.leaves.push(commitment);
        Ok(position)
    }
}
