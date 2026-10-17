//! Composition of spending and nullifier capabilities into an ownership commitment.

use super::{NullifierKey, SpendingKey};
use crate::{CryptoFramingError, domain::Domain, hash::poseidon2};
use houseki_types::{NetworkId, OwnershipCommitment};

impl SpendingKey {
    /// Derives the ownership commitment for this spending key and the supplied nullifier key.
    ///
    /// Both key commitments are derived under the supplied network before their public digests
    /// enter the `houseki/v1/ownership/commitment` transcript after the network bytes, with the
    /// spending commitment first and each 64 byte value framed separately.
    ///
    /// Secret bytes remain inside the guarded key commitment operations, while the final hash
    /// processes only public digests and leaves both borrowed keys available for later use.
    ///
    /// The returned value binds the supplied capabilities without constituting a proof of
    /// knowledge, spending authorization or a binding to a recipient's encryption key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoFramingError`] without an ownership commitment if either key commitment
    /// or the final transcript fails, although all parts currently have fixed lengths.
    pub fn ownership_commitment(
        &self,
        network: NetworkId,
        nullifier_key: &NullifierKey,
    ) -> Result<OwnershipCommitment, CryptoFramingError> {
        let spending = self.commitment(network)?;
        let nullifier = nullifier_key.commitment(network)?;

        let digest = poseidon2(
            Domain::OwnershipCommitment,
            &[
                network.as_bytes(),
                spending.as_bytes(),
                nullifier.as_bytes(),
            ],
        )?;

        Ok(OwnershipCommitment::from_bytes(digest))
    }
}

/// Complete ownership vectors, input coverage and separation of key roles.
#[cfg(test)]
mod tests {
    use super::{NetworkId, NullifierKey, SpendingKey};

    /// Checks both inner commitments and the final transcript against independent vectors.
    #[test]
    fn ownership_commitments_match_independent_vectors() {
        // Independent Python integer arithmetic evaluates all three transcripts with the
        // pinned public constants, explicit framing and direct matrix products.
        for (network, spending, nullifier, expected) in [
            (
                [0; 64],
                [0; 32],
                [0xff; 32],
                concat!(
                    "eabb46cdb9ab2b356c15564f1bb3426a1719afbf16ce5ae9ec4b0c85bace0d046",
                    "36d55c0fb5dd106d5587c6e1b34d5d7efd99c29fbdf711e7aef96e7f5a32fe0"
                ),
            ),
            (
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                std::array::from_fn(|i| u8::try_from(i + 32).unwrap()),
                concat!(
                    "31b5c84cb056541d623f1fcd4a8eaad71f988a60be15b399573502e7da5acf52b",
                    "d0306f92659dc8876680cf1f04172b9b327199f3899334fd068d3a94ee93147"
                ),
            ),
            (
                [0xff; 64],
                [0xff; 32],
                [0; 32],
                concat!(
                    "98a989ec9f52e0442517ba5a4c295e97afc3d6c7c56ff68c26ffbda2ec4f0aafa",
                    "4b45bbc15ca5d701daf62ff573fcd667aec8b5ed00b459f5b713fe93bc2e79b"
                ),
            ),
        ] {
            let spending = SpendingKey::from_bytes(&spending);
            let nullifier = NullifierKey::from_bytes(&nullifier);
            let commitment = spending
                .ownership_commitment(NetworkId::from_bytes(network), &nullifier)
                .unwrap();
            let actual: String = commitment
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            assert_eq!(actual, expected);
        }
    }

    /// Checks that the complete network and both complete keys contribute to ownership.
    #[test]
    fn ownership_binds_every_network_and_key_byte() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let spending_bytes = [0xa7; 32];
        let nullifier_bytes = [0x59; 32];
        let spending = SpendingKey::from_bytes(&spending_bytes);
        let nullifier = NullifierKey::from_bytes(&nullifier_bytes);
        let original = spending.ownership_commitment(network, &nullifier).unwrap();

        for index in 0..64 {
            let mut changed = *network.as_bytes();
            changed[index] ^= 1;
            let commitment = spending
                .ownership_commitment(NetworkId::from_bytes(changed), &nullifier)
                .unwrap();

            assert_ne!(commitment, original);
        }

        for index in 0..32 {
            let mut changed = spending_bytes;
            changed[index] ^= 1;
            let commitment = SpendingKey::from_bytes(&changed)
                .ownership_commitment(network, &nullifier)
                .unwrap();

            assert_ne!(commitment, original);
        }

        for index in 0..32 {
            let mut changed = nullifier_bytes;
            changed[index] ^= 1;
            let commitment = spending
                .ownership_commitment(network, &NullifierKey::from_bytes(&changed))
                .unwrap();

            assert_ne!(commitment, original);
        }

        assert_eq!(
            spending.ownership_commitment(network, &nullifier).unwrap(),
            original
        );
    }

    /// Checks that ownership preserves distinct roles and cannot substitute either component.
    #[test]
    fn ownership_is_ordered_and_separate_from_its_components() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let spending = SpendingKey::from_bytes(&[0xa7; 32]);
        let nullifier = NullifierKey::from_bytes(&[0x59; 32]);
        let original = spending.ownership_commitment(network, &nullifier).unwrap();
        let swapped = SpendingKey::from_bytes(&[0x59; 32])
            .ownership_commitment(network, &NullifierKey::from_bytes(&[0xa7; 32]))
            .unwrap();

        assert_ne!(original, swapped);
        assert_ne!(
            original.as_bytes(),
            spending.commitment(network).unwrap().as_bytes()
        );
        assert_ne!(
            original.as_bytes(),
            nullifier.commitment(network).unwrap().as_bytes()
        );
    }
}
