//! Owned protected paths with actual count bound root verification.

use houseki_crypto::{CryptoFramingError, note_membership_root};
use houseki_types::{NoteCommitment, NotePosition, NoteTreeAnchor};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// A failure of actual native membership without exposing private path values.
#[derive(Debug, Error)]
pub enum NoteMembershipError {
    /// The original position is outside the anchor's occupied prefix.
    #[error("note position is not occupied under the anchor")]
    PositionNotOccupied,

    /// The full recomputed count bound root differs from the selected anchor.
    #[error("note membership root does not match the anchor")]
    RootMismatch,

    /// Fixed guarded tree framing failed without membership success.
    #[error("could not derive note membership root: {0}")]
    Framing(
        /// Original safe fixed framing failure.
        #[from]
        CryptoFramingError,
    ),
}

/// Failure to select a sibling without exposing private path material.
#[cfg(feature = "proofs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProofPathAccessError {
    /// The requested sibling level is outside the fixed depth 64 path.
    #[error("invalid proof path level")]
    InvalidLevel,
}

/// A protected original position and exactly 64 sibling digests in leaf to root order.
///
/// Construction imports untrusted witness material without asserting membership or finality.
///
/// Stored position and siblings are cleared on drop, including unwinding, while caller import
/// buffers and every compiler or system copy remain outside this cleanup guarantee.
///
/// No cloning or detailed diagnostics are provided.
///
/// The `proofs` feature permits copying a single sibling into guarded caller storage.
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

    /// Copies one sibling in leaf to root order into an already guarded destination.
    ///
    /// The caller owns and clears the destination independently of this witness.
    ///
    /// # Errors
    ///
    /// Returns [`ProofPathAccessError::InvalidLevel`] for level 64 or larger without writing.
    ///
    /// ```compile_fail,E0308
    /// use houseki_state::NoteMembershipWitness;
    /// fn copy(witness: &NoteMembershipWitness) {
    ///     witness.write_proof_sibling(0, &mut [0; 64]).unwrap();
    /// }
    /// ```
    #[cfg(feature = "proofs")]
    pub fn write_proof_sibling(
        &self,
        level: usize,
        destination: &mut Zeroizing<[u8; 64]>,
    ) -> Result<(), ProofPathAccessError> {
        let sibling = self
            .siblings
            .get(level)
            .ok_or(ProofPathAccessError::InvalidLevel)?;
        destination.copy_from_slice(sibling);
        Ok(())
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

    /// Copies all sibling levels and preserves the destination for every invalid level.
    #[cfg(feature = "proofs")]
    #[test]
    fn proof_sibling_access_rejects_level_64_without_writing() {
        let siblings = std::array::from_fn(|level| [level as u8; 64]);
        let witness = NoteMembershipWitness::from_parts(&NotePosition::new(u64::MAX), &siblings);
        let mut destination = Zeroizing::new([255; 64]);
        for level in 0..64 {
            witness
                .write_proof_sibling(level, &mut destination)
                .unwrap();
            assert_eq!(*destination, [level as u8; 64]);
        }
        for level in [64, 65, usize::MAX] {
            destination.fill(251);
            assert!(matches!(
                witness.write_proof_sibling(level, &mut destination),
                Err(super::ProofPathAccessError::InvalidLevel)
            ));
            assert_eq!(*destination, [251; 64]);
        }
    }

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
