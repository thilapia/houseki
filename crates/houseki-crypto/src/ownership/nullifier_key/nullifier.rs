//! Keyed note nullifiers bound to the original insertion position.

use super::NullifierKey;
use crate::{CryptoFramingError, domain::Domain, hash::poseidon2_secret};
use houseki_types::{NetworkId, NoteCommitment, NotePosition, NoteVersion, Nullifier};
use zeroize::Zeroizing;

impl NullifierKey {
    /// Derives the spend marker for the supplied note commitment and original position.
    ///
    /// The guarded `houseki/v1/note/nullifier` transcript binds the network's 64 bytes, four
    /// little endian note version bytes, this key's 32 secret bytes, the 64 byte commitment
    /// and eight little endian position bytes as separate ordered parts.
    ///
    /// Position remains borrowed and its encoding stays guarded because membership witnesses
    /// may keep it private, with the caller responsible for the original position storage.
    ///
    /// The caller selects compatible note rules and checks version support in `houseki-notes`,
    /// then proves that this key, commitment and original position belong to the same opening
    /// and membership relation.
    ///
    /// Neither the current anchor nor transaction context enters the derivation, and the public
    /// key commitment cannot replace the secret key in this operation.
    ///
    /// The result does not establish spending authority, membership, tree capacity or unspentness,
    /// and both the key and position remain available to their owners after derivation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoFramingError`] without a nullifier if framing fails, although all parts
    /// currently have fixed lengths and every represented position fits its encoding.
    pub fn nullifier(
        &self,
        network: NetworkId,
        version: NoteVersion,
        commitment: NoteCommitment,
        original_position: &NotePosition,
    ) -> Result<Nullifier, CryptoFramingError> {
        let position_bytes = Zeroizing::new(original_position.value().to_le_bytes());
        let digest = poseidon2_secret(
            Domain::NoteNullifier,
            &[
                network.as_bytes(),
                &version.value().to_le_bytes(),
                &self.0,
                commitment.as_bytes(),
                &position_bytes[..],
            ],
        )?;

        Ok(Nullifier::from_bytes(*digest))
    }
}

/// Independent nullifier vectors, complete field coverage and reproducible note identity.
#[cfg(test)]
mod tests {
    use super::*;

    /// Checks the exact keyed transcript and integer byte order against independent vectors.
    #[test]
    fn note_nullifiers_match_independent_vectors() {
        // Independent Python integer arithmetic evaluates the complete framed transcript.
        // Version and position fixtures exercise encoding without asserting supported rules
        // or membership in a tree with that capacity.
        for (network, version, key, commitment, position, expected) in [
            (
                [0; 64],
                0,
                [0; 32],
                [0; 64],
                0,
                concat!(
                    "f7307e278b595477a6f91d2d8f35d83651c663f1a54f644a0880d234e634e0351",
                    "e27b8b1ea8afbb5c5c0f89acd82aeb6a80bb2c7b55c9b94ad66764c54882bba"
                ),
            ),
            (
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                0x01020304,
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                std::array::from_fn(|i| u8::try_from(i + 64).unwrap()),
                0x0102030405060708,
                concat!(
                    "248312082435dc7b7b02df9befc19937ac75cfbe61b1cc72149b73e6541a1770a",
                    "401dd986c058037301a05bdc6fb5858eb0ece74600ecc038db110c4ac24f37f"
                ),
            ),
            (
                [0xff; 64],
                u32::MAX,
                [0xff; 32],
                [0xff; 64],
                u64::MAX,
                concat!(
                    "1e8531dd8b637d358470bcba55b16dc95015c6a6348f896d03412f5cd5789f472",
                    "4a7d0cb573939a7b03023ab0e9787ba100db1c33a04e59bd4ada1724fe318b3"
                ),
            ),
        ] {
            let key = NullifierKey::from_bytes(&key);
            let result = key
                .nullifier(
                    NetworkId::from_bytes(network),
                    NoteVersion::new(version),
                    NoteCommitment::from_bytes(commitment),
                    &NotePosition::new(position),
                )
                .unwrap();
            let actual: String = result
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            assert_eq!(actual, expected);
        }
    }

    /// Checks every network, note version and commitment byte in the nullifier relation.
    #[test]
    fn nullifier_binds_complete_public_context() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let version = NoteVersion::new(0x01020304);
        let commitment = NoteCommitment::from_bytes([0x59; 64]);
        let key = NullifierKey::from_bytes(&[0xa7; 32]);
        let position = NotePosition::new(0x0102030405060708);
        let derive = |network, version, commitment| {
            key.nullifier(network, version, commitment, &position)
                .unwrap()
        };

        let original = derive(network, version, commitment);

        for index in 0..64 {
            let mut changed = *network.as_bytes();
            changed[index] ^= 1;

            assert_ne!(
                derive(NetworkId::from_bytes(changed), version, commitment),
                original
            );
        }

        for index in 0..4 {
            let changed = NoteVersion::new(version.value() ^ (1 << (index * 8)));

            assert_ne!(derive(network, changed, commitment), original);
        }

        for index in 0..64 {
            let mut changed = *commitment.as_bytes();
            changed[index] ^= 1;

            assert_ne!(
                derive(network, version, NoteCommitment::from_bytes(changed)),
                original
            );
        }
    }

    /// Checks complete secret and position binding while preserving reproducible derivation.
    #[test]
    fn nullifier_binds_key_and_original_position_without_consuming_them() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let version = NoteVersion::new(1);
        let commitment = NoteCommitment::from_bytes([0x59; 64]);
        let key_bytes = [0xa7; 32];
        let key = NullifierKey::from_bytes(&key_bytes);
        let position = NotePosition::new(0x0102030405060708);
        let original = key
            .nullifier(network, version, commitment, &position)
            .unwrap();

        for index in 0..32 {
            let mut changed = key_bytes;
            changed[index] ^= 1;
            let result = NullifierKey::from_bytes(&changed)
                .nullifier(network, version, commitment, &position)
                .unwrap();

            assert_ne!(result, original);
        }

        for index in 0..8 {
            let changed = NotePosition::new(position.value() ^ (1 << (index * 8)));
            let result = key
                .nullifier(network, version, commitment, &changed)
                .unwrap();

            assert_ne!(result, original);
        }

        assert_eq!(key.0, key_bytes);
        assert_eq!(position.value(), 0x0102030405060708);
        assert_eq!(
            key.nullifier(network, version, commitment, &position)
                .unwrap(),
            original
        );
    }
}
