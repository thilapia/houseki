//! Owned protected paths with actual count bound root verification.

mod error;

pub use error::NoteMembershipError;

use houseki_crypto::note_membership_root;
use houseki_types::{NoteCommitment, NotePosition, NoteTreeAnchor};
use std::fmt;
use zeroize::Zeroizing;

/// A protected original position and exactly 64 sibling digests in leaf to root order.
///
/// Construction imports untrusted witness material without asserting membership or finality.
///
/// Stored position and siblings are cleared on drop, including unwinding, while caller import
/// buffers and every compiler or system copy remain outside this cleanup guarantee.
///
/// No clone, detailed diagnostics or sibling byte export is provided.
pub struct NoteMembershipWitness {
    /// Original insertion position under an owner that performs explicit drop cleanup.
    pub(crate) position: Zeroizing<NotePosition>,

    /// Selected membership association retained in protected owned storage.
    pub(crate) siblings: Zeroizing<[[u8; 64]; 64]>,
}

impl NoteMembershipWitness {
    /// Copies exact borrowed witness fields into independent guarded owners without validation.
    pub fn from_parts(position: &NotePosition, siblings: &[[u8; 64]; 64]) -> Self {
        Self {
            position: Zeroizing::new(*position),
            siblings: Zeroizing::new(*siblings),
        }
    }

    /// Borrows the retained original position for the same note's nullifier relation.
    ///
    /// Explicit caller copies remain the caller's responsibility to protect and clear.
    pub fn original_position(&self) -> &NotePosition {
        &self.position
    }

    /// Verifies occupied position and the exact guarded root against declared anchor metadata.
    ///
    /// Every sibling level is processed by crypto's fixed depth protected operation after range checking.
    ///
    /// This does not authenticate the anchor's history or finality, check unspentness or grant authority.
    ///
    /// # Errors
    ///
    /// Rejects an unoccupied position before hashing, then preserves framing errors and requires
    /// exact root equality without returning intermediate private path values.
    pub fn verify(
        &self,
        anchor: &NoteTreeAnchor,
        commitment: &NoteCommitment,
    ) -> Result<(), NoteMembershipError> {
        if u128::from(self.position.value()) >= anchor.count().value() {
            return Err(NoteMembershipError::PositionNotOccupied);
        }

        let root = note_membership_root(
            anchor.network_id(),
            anchor.count(),
            commitment,
            &self.position,
            &self.siblings,
        )?;

        if root != anchor.root() {
            return Err(NoteMembershipError::RootMismatch);
        }

        Ok(())
    }
}

impl fmt::Debug for NoteMembershipWitness {
    /// Writes a fixed redacted label without formatting position or siblings.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoteMembershipWitness([REDACTED])")
    }
}

/// Actual path verification and adversarial count, position and sibling binding.
#[cfg(test)]
mod tests {
    use crate::{NoteMembershipError, NoteMembershipWitness, NoteTree};
    use houseki_types::{NetworkId, NoteCommitment, NoteCount, NotePosition, NoteTreeAnchor};
    use zeroize::Zeroizing;

    /// Requires the exact occupied prefix, network, commitment and each private sibling level.
    #[test]
    fn actual_membership_rejects_changed_anchor_commitment_position_and_siblings() {
        let network = NetworkId::from_bytes([7; 64]);
        let commitment = NoteCommitment::from_bytes([11; 64]);
        let mut tree = NoteTree::new(network).unwrap();
        let position = tree.append(commitment).unwrap();
        tree.append(NoteCommitment::from_bytes([12; 64])).unwrap();
        let anchor = tree.anchor();
        let witness = tree.witness(&position).unwrap();

        witness.verify(&anchor, &commitment).unwrap();

        for level in 0..64 {
            let mut changed = Zeroizing::new(*witness.siblings);
            changed[level][63] ^= 1;
            let changed = NoteMembershipWitness::from_parts(&position, &changed);

            assert!(matches!(
                changed.verify(&anchor, &commitment),
                Err(NoteMembershipError::RootMismatch)
            ));
        }

        assert!(matches!(
            witness.verify(&anchor, &NoteCommitment::from_bytes([10; 64])),
            Err(NoteMembershipError::RootMismatch)
        ));

        let changed = NoteMembershipWitness::from_parts(&NotePosition::new(1), &witness.siblings);

        assert!(matches!(
            changed.verify(&anchor, &commitment),
            Err(NoteMembershipError::RootMismatch)
        ));

        for position in [2, 1_u64 << 32, u64::MAX] {
            let changed =
                NoteMembershipWitness::from_parts(&NotePosition::new(position), &witness.siblings);

            assert!(matches!(
                changed.verify(&anchor, &commitment),
                Err(NoteMembershipError::PositionNotOccupied)
            ));
        }

        let changed = NoteTreeAnchor::new(network, NoteCount::new(1).unwrap(), anchor.root());

        assert!(matches!(
            witness.verify(&changed, &commitment),
            Err(NoteMembershipError::RootMismatch)
        ));

        let changed = NoteTreeAnchor::new(
            NetworkId::from_bytes([6; 64]),
            anchor.count(),
            anchor.root(),
        );

        assert!(matches!(
            witness.verify(&changed, &commitment),
            Err(NoteMembershipError::RootMismatch)
        ));

        assert_eq!(witness.original_position(), &position);
        witness.verify(&anchor, &commitment).unwrap();
    }

    /// Imports independent protected owners and keeps diagnostics fixed across all witness material.
    #[test]
    fn witness_import_is_owned_guarded_and_redacted() {
        let mut position = NotePosition::new(u64::MAX);
        let mut siblings = [[0xff; 64]; 64];
        let witness = NoteMembershipWitness::from_parts(&position, &siblings);

        position = NotePosition::new(0);
        siblings.fill([0; 64]);

        assert_eq!(witness.original_position().value(), u64::MAX);
        assert_eq!(&*witness.siblings, &[[0xff; 64]; 64]);
        assert_eq!(format!("{witness:?}"), "NoteMembershipWitness([REDACTED])");
        assert_eq!(format!("{witness:#?}"), "NoteMembershipWitness([REDACTED])");
        assert_eq!(position.value(), 0);
        assert_eq!(siblings, [[0; 64]; 64]);
    }
}
