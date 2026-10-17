//! Fixed note commitment hashing with an internally derived recipient binding.

use super::CryptoSuite;
use crate::{
    CryptoFramingError, MlKem1024EncapsulationKey, domain::Domain, hash::poseidon2_secret,
};
use houseki_types::{Amount, NetworkId, NoteCommitment, NoteVersion, OwnershipCommitment};
use zeroize::Zeroizing;

impl CryptoSuite {
    /// Derives a note commitment from its typed fields and borrowed private opening material.
    ///
    /// Recipient binding is derived from the network, this suite and the validated public key
    /// before the guarded `houseki/v1/note/commitment` transcript binds the network, note version,
    /// ownership commitment, recipient binding, amount and blinding as separate ordered parts.
    ///
    /// Network and digest parts occupy 64 bytes each, while the version uses four little endian
    /// bytes, the bounded amount uses sixteen and blinding supplies exactly 32 bytes.
    ///
    /// The caller selects note rules compatible with this fixed profile and checks version
    /// support in `houseki-notes`, since encoding a version here does not recognize its rules.
    ///
    /// This primitive also accepts zero amounts, leaving ordinary note amount rules and
    /// protocol activation with the consumer.
    ///
    /// Amount and blinding remain borrowed, with encoded amount bytes guarded during hashing
    /// and the caller responsible for their original storage and fresh independent blinding.
    ///
    /// The result binds the supplied fields without establishing an ownership opening,
    /// recipient identity, membership or spending authority.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoFramingError`] if recipient binding or the note transcript fails, with
    /// no note commitment returned and all present input lengths fixed and representable.
    pub fn note_commitment(
        &self,
        network: NetworkId,
        version: NoteVersion,
        ownership: OwnershipCommitment,
        recipient_key: &MlKem1024EncapsulationKey,
        amount: &Amount,
        blinding: &[u8; 32],
    ) -> Result<NoteCommitment, CryptoFramingError> {
        match self {
            Self::V1 => {
                let recipient = self.recipient_key_binding(network, recipient_key)?;
                let amount_bytes = Zeroizing::new(amount.to_le_bytes());

                let digest = poseidon2_secret(
                    Domain::NoteCommitment,
                    &[
                        network.as_bytes(),
                        &version.value().to_le_bytes(),
                        ownership.as_bytes(),
                        &recipient,
                        &amount_bytes[..],
                        blinding,
                    ],
                )?;

                Ok(NoteCommitment::from_bytes(*digest))
            }
        }
    }
}

/// Complete note vectors, input coverage and private opening material binding.
#[cfg(test)]
mod tests {
    use super::*;
    use houseki_types::EncodedMlKem1024PublicKey;

    /// Builds a canonical key fixture with zero polynomial coefficients and a chosen seed.
    fn key(seed: u8) -> MlKem1024EncapsulationKey {
        let mut bytes = [0; 1568];
        bytes[1536..].fill(seed);

        MlKem1024EncapsulationKey::try_from(&EncodedMlKem1024PublicKey::from_bytes(bytes)).unwrap()
    }

    /// Checks complete integer vectors for primitive encodings and positive V1 note amounts.
    #[test]
    fn note_commitments_match_independent_vectors() {
        // Independent Python arithmetic evaluates both transcripts with pinned public constants.
        // The arbitrary versions exercise primitive encoding, while the V1 fixtures cover
        // positive amounts without asserting honest key generation or blinding freshness.
        for (network, version, ownership, seed, atoms, blinding, expected) in [
            (
                [0; 64],
                0,
                [0; 64],
                0,
                0,
                [0; 32],
                concat!(
                    "1afa3d6a15fecc8cc45cb1aa47782aaade7c9bef1f6a3795d39b059a8161048a0",
                    "a65f2c498056a99504f07e736e1684353ee78d48e28f8faba58e012dd2e73d9"
                ),
            ),
            (
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                0x01020304,
                std::array::from_fn(|i| u8::try_from(i + 64).unwrap()),
                0xa5,
                (1_u128 << 64) + 0x01020304,
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                concat!(
                    "b7cbfa3659cbd2c222b99728d85ca86cddc2b75c2bc573411df0b903628e90ee9",
                    "965a416c3039f55d0f6295d75f76ae7b60ba0d60d2e85422315a037bb0b3162"
                ),
            ),
            (
                [0xff; 64],
                u32::MAX,
                [0xff; 64],
                0xff,
                Amount::MAX_ATOMS,
                [0xff; 32],
                concat!(
                    "6393a37c316be92ed2fe487692388a4db67528aecfa1efc630980b87f7f467b4ac",
                    "47aaf2ec8fd082dd80f5e8e325ab5ad81b73f61af0001ac45b0728c743bf41"
                ),
            ),
            (
                [0; 64],
                1,
                [0; 64],
                0,
                1,
                [0; 32],
                concat!(
                    "67519504e20c7223a5068feae0c831bdfe180fcc11b6b597c5d8a4506d592c41",
                    "decf8a6608538e3c875bcd61322d8a832f554417b2bc5a32f4cde0454adb20f0"
                ),
            ),
            (
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                1,
                std::array::from_fn(|i| u8::try_from(i + 64).unwrap()),
                0xa5,
                (1_u128 << 64) + 0x01020304,
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                concat!(
                    "e4d71a009781bebee473503ea001250799bbe6993cd0f8abd19af0831ebfd7bc9",
                    "613c3c3e38b39b64f3e2669430253fe98e152ec550823b91554f89adf83ec89"
                ),
            ),
            (
                [0xff; 64],
                1,
                [0xff; 64],
                0xff,
                Amount::MAX_ATOMS,
                [0xff; 32],
                concat!(
                    "4de99cdcc2d1080fca897f80fff6e7de81859b438d21ccc9277cb9b964a14853b",
                    "d2081e4214719bfcbbbae16fdc0f529203dfb118d338517c89209e4930ad825"
                ),
            ),
        ] {
            let commitment = CryptoSuite::V1
                .note_commitment(
                    NetworkId::from_bytes(network),
                    NoteVersion::new(version),
                    OwnershipCommitment::from_bytes(ownership),
                    &key(seed),
                    &Amount::from_atoms(atoms).unwrap(),
                    &blinding,
                )
                .unwrap();
            let actual: String = commitment
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            assert_eq!(actual, expected);
        }
    }

    /// Checks every network, version and ownership byte in the committed context.
    #[test]
    fn note_commitment_binds_complete_public_context() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let version = NoteVersion::new(0x01020304);
        let ownership = OwnershipCommitment::from_bytes([0x59; 64]);
        let key = key(0);
        let amount = Amount::from_atoms(1).unwrap();

        let derive = |network, version, ownership| {
            CryptoSuite::V1
                .note_commitment(network, version, ownership, &key, &amount, &[0xa7; 32])
                .unwrap()
        };

        let original = derive(network, version, ownership);

        for index in 0..64 {
            let mut changed = *network.as_bytes();
            changed[index] ^= 1;

            assert_ne!(
                derive(NetworkId::from_bytes(changed), version, ownership),
                original
            );
        }

        for index in 0..4 {
            let changed = NoteVersion::new(version.value() ^ (1 << (index * 8)));

            assert_ne!(derive(network, changed, ownership), original);
        }

        for index in 0..64 {
            let mut changed = *ownership.as_bytes();
            changed[index] ^= 1;

            assert_ne!(
                derive(network, version, OwnershipCommitment::from_bytes(changed)),
                original
            );
        }
    }

    /// Checks that the note binds a recipient derived from the full validated public key.
    #[test]
    fn note_commitment_binds_recipient_polynomials_and_seed() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let version = NoteVersion::new(1);
        let ownership = OwnershipCommitment::from_bytes([0x59; 64]);
        let amount = Amount::from_atoms(1).unwrap();
        let derive = |key: &MlKem1024EncapsulationKey| {
            CryptoSuite::V1
                .note_commitment(network, version, ownership, key, &amount, &[0xa7; 32])
                .unwrap()
        };

        let original = derive(&key(0));

        for index in [0, 384, 768, 1152, 1535, 1536, 1567] {
            let mut bytes = [0; 1568];
            bytes[index] = 1;
            let changed =
                MlKem1024EncapsulationKey::try_from(&EncodedMlKem1024PublicKey::from_bytes(bytes))
                    .unwrap();

            assert_ne!(derive(&changed), original);
        }
    }

    /// Checks all representable amount byte positions and every blinding byte without mutation.
    #[test]
    fn note_commitment_binds_borrowed_amount_and_blinding() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let version = NoteVersion::new(1);
        let ownership = OwnershipCommitment::from_bytes([0x59; 64]);
        let key = key(0);
        let amount = Amount::from_atoms(0).unwrap();
        let blinding = [0xa7; 32];

        let derive = |amount: &Amount, blinding: &[u8; 32]| {
            CryptoSuite::V1
                .note_commitment(network, version, ownership, &key, amount, blinding)
                .unwrap()
        };

        let original = derive(&amount, &blinding);

        for index in 0..13 {
            let changed = Amount::from_atoms(1_u128 << (index * 8)).unwrap();

            assert_ne!(derive(&changed, &blinding), original);
        }

        for index in 0..32 {
            let mut changed = blinding;
            changed[index] ^= 1;

            assert_ne!(derive(&amount, &changed), original);
        }

        assert_eq!(amount.atoms(), 0);
        assert_eq!(blinding, [0xa7; 32]);
        assert_eq!(derive(&amount, &blinding), original);
    }
}
