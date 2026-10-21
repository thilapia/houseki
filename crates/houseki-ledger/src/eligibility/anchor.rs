//! Trusted descriptor resolution independent of current anchor eligibility.

use crate::{ParentSnapshot, ReplayInputs, UnitPreparationError};
use houseki_types::{NoteRoot, NoteTreeAnchor};

/// Resolves a unique trusted descriptor, retaining recognition independently of expiry.
pub(super) fn resolve_anchor(
    parent: &ParentSnapshot,
    root: NoteRoot,
) -> Result<NoteTreeAnchor, UnitPreparationError> {
    let mut found = None;
    let mut consider = |anchor: NoteTreeAnchor| -> Result<(), UnitPreparationError> {
        if anchor.root() == root {
            if anchor.network_id() != parent.state().network()
                || found.is_some_and(|previous| previous != anchor)
            {
                return Err(UnitPreparationError::Integrity);
            }
            found = Some(anchor);
        }
        Ok(())
    };
    for anchor in parent.known_anchors() {
        consider(anchor)?;
    }
    for anchor in parent.state().anchors() {
        consider(anchor.anchor())?;
    }
    match parent.replay_inputs() {
        ReplayInputs::Bootstrap(manifest) => {
            for anchor in &manifest.anchors {
                consider(anchor.anchor())?;
            }
        }
        ReplayInputs::Execution {
            trusted_anchors, ..
        } => {
            for &anchor in trusted_anchors.iter() {
                consider(anchor)?;
            }
        }
    }
    found.ok_or(UnitPreparationError::UnresolvedAnchor)
}

/// Trusted descriptor lookup cases.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::trusted_manifest;
    use crate::validate_bootstrap;
    use houseki_types::{CheckpointSequence, NoteRoot};

    /// Resolves only an actual authenticated root/count/network descriptor.
    #[test]
    fn anchor_resolution_requires_trusted_count_network() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        assert_eq!(
            resolve_anchor(&parent, parent.state().note_anchor().root()).unwrap(),
            parent.state().note_anchor()
        );
        assert!(matches!(
            resolve_anchor(&parent, NoteRoot::from_bytes([0; 64])),
            Err(crate::UnitPreparationError::UnresolvedAnchor)
        ));
    }

    /// Expiry is an execution decision and does not erase an understood proof descriptor.
    #[test]
    fn expired_known_anchor_still_resolves() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let rules =
            crate::CheckpointRules::derive(parent.state(), CheckpointSequence::new(64)).unwrap();
        assert!(!rules.eligible_sequences().contains(&0));
        assert!(resolve_anchor(&parent, parent.state().note_anchor().root()).is_ok());
    }
}
