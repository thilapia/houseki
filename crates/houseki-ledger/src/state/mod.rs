//! Immutable logical state and independently owned working trees.

mod anchor;
mod error;
mod logical;
mod working;
pub use anchor::AnchorRecord;
pub use error::StateError;
pub use logical::LogicalState;
pub use working::WorkingState;

/// Working-state isolation and resource validation tests.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use crate::test_support::manifest;
    use crate::{StateError, WorkingState};
    use houseki_types::{NoteCommitment, Nullifier};

    /// Appending twice to a reconstructed tree leaves the parent root, count and leaves intact.
    #[test]
    fn working_tree_is_independent() {
        let candidate = manifest().candidate().unwrap();
        let parent = candidate.state();
        let anchor = parent.note_anchor();
        let leaves = parent.leaves().to_vec();
        let mut working = WorkingState::reconstruct(parent).unwrap();
        working.append(NoteCommitment::from_bytes([3; 64])).unwrap();
        working.append(NoteCommitment::from_bytes([3; 64])).unwrap();
        assert_eq!(parent.note_anchor(), anchor);
        assert_eq!(parent.leaves(), leaves);
        assert_eq!(working.state().leaves().len(), 3);
        assert_eq!(
            &working.state().leaves()[1..],
            &[NoteCommitment::from_bytes([3; 64]); 2]
        );
        assert_ne!(working.state().note_anchor(), anchor);
        working.validate_conservation().unwrap();
    }

    /// Corrupt or excessive spent state cannot be promoted by reconstruction.
    #[test]
    fn reconstruction_rechecks_spent_capacity() {
        let mut candidate = manifest().candidate().unwrap();
        for i in 0_u64..4097 {
            let mut bytes = [0; 64];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            candidate
                .state
                .spent
                .insert(bytes, Nullifier::from_bytes(bytes));
        }
        assert!(matches!(
            WorkingState::reconstruct(&candidate.state),
            Err(StateError::Capacity)
        ));
    }
}
