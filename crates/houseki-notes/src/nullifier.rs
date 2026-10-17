//! Fixed note nullifier orchestration from a protected opening and original position.

use houseki_crypto::{CryptoFramingError, CryptoSuite, NullifierKey};
use houseki_types::{NotePosition, Nullifier};

use crate::{NoteFormat, NoteOpening};

/// Derives the fixed nullifier from this opening and its original insertion position.
///
/// The retained immutable note format and recipient suite select the supported rules.
///
/// Commitment derivation uses the opening's original guarded material, then crypto borrows
/// the supplied key and full position to bind network, note version and commitment.
///
/// The result is independent of the current anchor, protocol version and delivery context.
///
/// Both key and position remain borrowed, with crypto guarding its temporary position encoding.
///
/// The caller remains responsible for ownership and cleanup of the original position storage.
///
/// Derivation does not verify key linkage to the declared ownership, original position
/// correctness, membership, tree capacity, spending authority or unspentness.
///
/// # Errors
///
/// Returns the original [`CryptoFramingError`] if commitment or nullifier framing fails,
/// without returning a partial result or including private opening values.
pub fn derive_nullifier(
    opening: &NoteOpening,
    key: &NullifierKey,
    position: &NotePosition,
) -> Result<Nullifier, CryptoFramingError> {
    match (opening.format(), opening.recipient().suite()) {
        (NoteFormat::V1, CryptoSuite::V1) => key.nullifier(
            opening.recipient().context().network_id(),
            opening.format().version(),
            opening.commitment()?,
            position,
        ),
    }
}

/// Independent complete positive V1 vectors and separation of original note identity.
#[cfg(test)]
mod tests {
    use houseki_crypto::{CryptoSuite, NullifierKey};
    use houseki_types::{
        AddressContext, AddressFormatVersion, Amount, EncodedMlKem1024PublicKey, NetworkId,
        NotePosition, OwnershipCommitment, RecipientDescriptor,
    };

    use crate::{NoteBlinding, NoteFormat, NoteOpening, NoteRecipient, derive_nullifier};

    /// Uses the minimum positive V1 fixture with canonical zero public coefficients and seed.
    fn opening(network: [u8; 64], atoms: u128, blinding: u8) -> NoteOpening {
        let network = NetworkId::from_bytes(network);
        let recipient = NoteRecipient::validate(
            &RecipientDescriptor::new(
                AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
                OwnershipCommitment::from_bytes([0; 64]),
                EncodedMlKem1024PublicKey::from_bytes([0; 1568]),
            ),
            network,
        )
        .unwrap();
        NoteOpening::new(
            NoteFormat::V1,
            &recipient,
            Amount::from_atoms(atoms).unwrap(),
            NoteBlinding::from_bytes(&[blinding; 32]),
        )
        .unwrap()
    }

    /// Checks the complete independent E, C and NF fixture at full original position boundaries.
    #[test]
    fn nullifiers_match_independent_positive_v1_vectors() {
        let opening = opening([0; 64], 1, 0);
        let key = NullifierKey::from_bytes(&[0; 32]);
        // Independent Python integer arithmetic recomputes E and C before each NF transcript.
        for (position, expected) in [
            (
                0_u64,
                "d14b37fafedb5fd0e98a0a36190f915da4c8c24fd42b32eef9436e11968cf5039450ed9a013e6eca5f551b94fc6f5401055c7dd5b67615ef2195513b925b50bd",
            ),
            (
                4294967297_u64,
                "00ea42f869b4d908b98801d21e4e6548030247cd1be79f3d5eec52878f4597d6279596c08cd5117109dcfe382f8a251bfe37f6ec1370541af7c6567a8dc048ef",
            ),
            (
                9223372036854775808_u64,
                "bac21255494683ae86b5f4270fa2d3f8619714eda2d16eac33280016fc0e1b0291e35a7d0aa91dff0e85d1f22f3a3fa265abd47da24fdfb3ab0151ad07f240af",
            ),
            (
                18446744073709551615_u64,
                "d2226cf5580a1d7ed2af6d9fc18d5b57d29e074d0335d1ab2c9635e0387dd68e148bb4e8cd09f5581d86368cf14072352849c8cb06efbbf9045698621f1bf791",
            ),
        ] {
            let position = NotePosition::new(position);
            let actual = derive_nullifier(&opening, &key, &position).unwrap();
            let actual: String = actual
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(actual, expected);
        }
    }

    /// Distinguishes changed positions, keys, network and note material while preserving inputs.
    #[test]
    fn nullifier_derivation_binds_original_position_key_and_opening() {
        let opening = opening([0; 64], 1, 0);
        let key = NullifierKey::from_bytes(&[0; 32]);
        let position = NotePosition::new(0);
        let original = derive_nullifier(&opening, &key, &position).unwrap();
        let commitment = opening.commitment().unwrap();
        for index in 0..8 {
            let changed = NotePosition::new(1 << (index * 8));
            assert_ne!(
                derive_nullifier(&opening, &key, &changed).unwrap(),
                original
            );
        }
        for index in 0..32 {
            let mut bytes = [0; 32];
            bytes[index] = 1;
            let changed = NullifierKey::from_bytes(&bytes);
            assert_ne!(
                derive_nullifier(&opening, &changed, &position).unwrap(),
                original
            );
        }
        for index in 0..64 {
            let mut network = [0; 64];
            network[index] = 1;
            let changed = self::opening(network, 1, 0);
            assert_ne!(
                derive_nullifier(&changed, &key, &position).unwrap(),
                original
            );
        }
        for changed in [
            self::opening([0; 64], 2, 0),
            self::opening([0; 64], Amount::MAX_ATOMS, 0),
            self::opening([0; 64], 1, 1),
        ] {
            assert_ne!(
                derive_nullifier(&changed, &key, &position).unwrap(),
                original
            );
        }
        assert_eq!(position.value(), 0);
        assert_eq!(opening.amount().atoms(), 1);
        assert_eq!(opening.commitment().unwrap(), commitment);
        assert_eq!(
            derive_nullifier(&opening, &key, &position).unwrap(),
            original
        );
    }
}
