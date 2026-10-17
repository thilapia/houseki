//! Native spending equations over actual ownership keys and concrete membership paths.

mod error;

pub use error::SpendRelationError;

use crate::SpendWitness;
use houseki_types::{NoteTreeAnchor, Nullifier};

/// Checks supported note rules, network, linked ownership, actual membership and declared nullifier.
///
/// The same protected original position feeds membership and nullifier derivation.
///
/// This is a native reference relation rather than proof verification or a knowledge argument.
///
/// Consumers separately authenticate anchor history, check eligibility and unspentness, bind the
/// complete payment statement and enforce active protocol and fee rules.
///
/// # Errors
///
/// Checks network and ownership before deriving C and verifying the concrete path, then requires
/// exact equality with the supplied public input marker, retaining safe framing and path sources.
pub fn check_spend(
    anchor: &NoteTreeAnchor,
    expected_nullifier: Nullifier,
    witness: &SpendWitness<'_>,
) -> Result<(), SpendRelationError> {
    let opening = witness.opening;
    let recipient = opening.recipient();

    match (opening.format(), recipient.suite()) {
        (crate::NoteFormat::V1, houseki_crypto::CryptoSuite::V1) => {}
    }

    if recipient.context().network_id() != anchor.network_id() {
        return Err(SpendRelationError::NetworkMismatch);
    }

    let ownership = witness
        .spending_key
        .ownership_commitment(anchor.network_id(), witness.nullifier_key)?;
    if ownership != recipient.ownership_commitment() {
        return Err(SpendRelationError::OwnershipMismatch);
    }

    let commitment = opening.commitment()?;
    witness.membership.verify(anchor, &commitment)?;

    let nullifier = crate::derive_nullifier(
        opening,
        witness.nullifier_key,
        witness.membership.original_position(),
    )?;
    if nullifier != expected_nullifier {
        return Err(SpendRelationError::NullifierMismatch);
    }

    Ok(())
}

/// Actual ownership and membership rather than caller declared verification Booleans.
#[cfg(test)]
mod tests {
    use crate::{
        NoteBlinding, NoteFormat, NoteOpening, NoteRecipient, SpendRelationError, SpendWitness,
        check_spend, derive_nullifier,
    };
    use houseki_crypto::{CryptoSuite, MlKem1024DecapsulationKey, NullifierKey, SpendingKey};
    use houseki_state::{NoteMembershipWitness, NoteTree};
    use houseki_types::*;

    /// Creates an independently owned recipient snapshot from the actual linked capabilities.
    fn recipient(
        network: NetworkId,
        spending: &SpendingKey,
        nullifier: &NullifierKey,
        key: &MlKem1024DecapsulationKey,
    ) -> NoteRecipient {
        NoteRecipient::validate(
            &RecipientDescriptor::new(
                AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
                spending.ownership_commitment(network, nullifier).unwrap(),
                key.encapsulation_key().to_encoded(),
            ),
            network,
        )
        .unwrap()
    }

    /// Builds one positive protected ordinary note from deterministic private fixtures.
    fn opening(recipient: &NoteRecipient, amount: u128, rho: u8) -> NoteOpening {
        NoteOpening::new(
            NoteFormat::V1,
            recipient,
            Amount::from_atoms(amount).unwrap(),
            NoteBlinding::from_bytes(&[rho; 32]),
        )
        .unwrap()
    }

    /// Verifies actually inserted duplicate commitments at distinct original positions and markers.
    #[test]
    fn native_spends_verify_actual_membership_and_original_position_identity() {
        let network = NetworkId::from_bytes([7; 64]);
        let spending = SpendingKey::from_bytes(&[0xa7; 32]);
        let nullifier = NullifierKey::from_bytes(&[0x59; 32]);
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(network, &spending, &nullifier, &key);
        let opening = opening(&recipient, 23, 0xa5);

        let mut tree = NoteTree::new(network).unwrap();
        let first = tree.append(opening.commitment().unwrap()).unwrap();
        let second = tree.append(opening.commitment().unwrap()).unwrap();

        let anchor = tree.anchor();
        let first_path = tree.witness(&first).unwrap();
        let second_path = tree.witness(&second).unwrap();

        let first_marker = derive_nullifier(&opening, &nullifier, &first).unwrap();
        let second_marker = derive_nullifier(&opening, &nullifier, &second).unwrap();

        assert_ne!(first_marker, second_marker);

        let witness = SpendWitness::new(&opening, &spending, &nullifier, &first_path);

        check_spend(&anchor, first_marker, &witness).unwrap();
        check_spend(
            &anchor,
            second_marker,
            &SpendWitness::new(&opening, &spending, &nullifier, &second_path),
        )
        .unwrap();

        assert!(matches!(
            check_spend(
                &anchor,
                first_marker,
                &SpendWitness::new(&opening, &spending, &nullifier, &second_path)
            ),
            Err(SpendRelationError::NullifierMismatch)
        ));

        assert_eq!(format!("{witness:?}"), "SpendWitness([REDACTED])");
        assert_eq!(opening.amount().atoms(), 23);
        check_spend(&anchor, first_marker, &witness).unwrap();
    }

    /// Rejects independently changed secrets, opening fields, occupied position, root and public marker.
    #[test]
    fn native_spends_reject_unlinked_keys_openings_paths_and_markers() {
        let network = NetworkId::from_bytes([7; 64]);
        let spending = SpendingKey::from_bytes(&[0xa7; 32]);
        let nullifier = NullifierKey::from_bytes(&[0x59; 32]);
        let key = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = recipient(network, &spending, &nullifier, &key);
        let opening = opening(&recipient, 23, 0xa5);

        let mut tree = NoteTree::new(network).unwrap();
        let position = tree.append(opening.commitment().unwrap()).unwrap();
        let path = tree.witness(&position).unwrap();
        let anchor = tree.anchor();

        let marker = derive_nullifier(&opening, &nullifier, &position).unwrap();

        let wrong_spending = SpendingKey::from_bytes(&[0xa6; 32]);

        assert!(matches!(
            check_spend(
                &anchor,
                marker,
                &SpendWitness::new(&opening, &wrong_spending, &nullifier, &path)
            ),
            Err(SpendRelationError::OwnershipMismatch)
        ));

        let wrong_nullifier = NullifierKey::from_bytes(&[0x58; 32]);

        assert!(matches!(
            check_spend(
                &anchor,
                marker,
                &SpendWitness::new(&opening, &spending, &wrong_nullifier, &path)
            ),
            Err(SpendRelationError::OwnershipMismatch)
        ));

        for changed in [
            self::opening(&recipient, 24, 0xa5),
            self::opening(&recipient, 23, 0xa4),
            self::opening(
                &self::recipient(
                    network,
                    &spending,
                    &nullifier,
                    &MlKem1024DecapsulationKey::from_seed(&[12; 64]),
                ),
                23,
                0xa5,
            ),
        ] {
            assert!(matches!(
                check_spend(
                    &anchor,
                    marker,
                    &SpendWitness::new(&changed, &spending, &nullifier, &path)
                ),
                Err(SpendRelationError::Membership(_))
            ));
        }

        let wrong_anchor = NoteTreeAnchor::new(
            NetworkId::from_bytes([6; 64]),
            anchor.count(),
            anchor.root(),
        );

        assert!(matches!(
            check_spend(
                &wrong_anchor,
                marker,
                &SpendWitness::new(&opening, &spending, &nullifier, &path)
            ),
            Err(SpendRelationError::NetworkMismatch)
        ));

        let wrong_anchor =
            NoteTreeAnchor::new(network, anchor.count(), NoteRoot::from_bytes([0; 64]));

        assert!(matches!(
            check_spend(
                &wrong_anchor,
                marker,
                &SpendWitness::new(&opening, &spending, &nullifier, &path)
            ),
            Err(SpendRelationError::Membership(_))
        ));

        let wrong_path = NoteMembershipWitness::from_parts(&NotePosition::new(1), &[[0; 64]; 64]);

        assert!(matches!(
            check_spend(
                &anchor,
                marker,
                &SpendWitness::new(&opening, &spending, &nullifier, &wrong_path)
            ),
            Err(SpendRelationError::Membership(_))
        ));
        assert!(matches!(
            check_spend(
                &anchor,
                Nullifier::from_bytes([0; 64]),
                &SpendWitness::new(&opening, &spending, &nullifier, &path)
            ),
            Err(SpendRelationError::NullifierMismatch)
        ));

        check_spend(
            &anchor,
            marker,
            &SpendWitness::new(&opening, &spending, &nullifier, &path),
        )
        .unwrap();
    }
}
