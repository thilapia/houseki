//! Internal spending key commitments for the ownership relation.

use super::SpendingKey;
use crate::{CryptoFramingError, domain::Domain, hash::poseidon2_secret};
use houseki_types::NetworkId;

/// The public digest binding one spending secret to its network and cryptographic role.
///
/// Construction requires a spending key, while the digest alone establishes neither knowledge
/// of that key nor authorization to spend a note.
pub(crate) struct SpendingKeyCommitment(
    /// Complete derived digest in the profile's little endian output encoding.
    [u8; 64],
);

impl SpendingKeyCommitment {
    /// Borrows the complete public digest for composition into the ownership commitment.
    pub(crate) fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl SpendingKey {
    /// Derives the internal spending commitment under the supplied network.
    ///
    /// The `houseki/v1/ownership/spend-key` transcript contains the network's 64 bytes followed
    /// by this key's 32 bytes as separate parts, using the guarded Poseidon2 profile.
    ///
    /// Only the resulting public digest leaves guarded storage, and the key remains available
    /// for later ownership operations without exposing its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoFramingError`] if framing cannot be represented or completed, although
    /// both parts currently have fixed lengths.
    pub(crate) fn commitment(
        &self,
        network: NetworkId,
    ) -> Result<SpendingKeyCommitment, CryptoFramingError> {
        let digest = poseidon2_secret(
            Domain::SpendingKeyCommitment,
            &[network.as_bytes(), &self.0],
        )?;

        Ok(SpendingKeyCommitment(*digest))
    }
}

/// Independent commitment vectors, complete input coverage and role separation.
#[cfg(test)]
mod tests {
    use super::{NetworkId, SpendingKey};
    use crate::{domain::Domain, hash::poseidon2};

    /// Checks the exact domain, part order and complete hash profile against integer vectors.
    #[test]
    fn spending_commitments_match_independent_vectors() {
        // Independent Python integer arithmetic with the pinned public constants evaluates
        // the explicit frame, full matrix products and modular powers before extraction.
        for (network, key, expected) in [
            (
                [0; 64],
                [0; 32],
                concat!(
                    "2ca91de1c497fcf205aac4fbc2fcd25200f68355b9339b628f2ac8fe55995e30ee",
                    "1c165304dd02e61fab7bcb1cb5a314805a584b1e54287e36201fd949804ba9"
                ),
            ),
            (
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                concat!(
                    "32eb9211d59006508e3718ad496f5001c5f18b84ca5b3065963828b2d059d9d3f",
                    "36df2be4b76357fb7687d54c7a739b1067af313f30c3214af997315dc25b7c0"
                ),
            ),
            (
                [0xff; 64],
                [0xff; 32],
                concat!(
                    "624e12ded397525e5da40e9284ff428a38c2cf91e34ddd6c026a41b4508c45d1f",
                    "a0468d7a832d6aa9fa8d35bbddee7901046d3780883807978ae9815cfae44c6"
                ),
            ),
        ] {
            let key = SpendingKey::from_bytes(&key);
            let commitment = key.commitment(NetworkId::from_bytes(network)).unwrap();
            let actual: String = commitment
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();

            assert_eq!(actual, expected);
        }
    }

    /// Checks that no network or key byte is omitted from the committed relation.
    #[test]
    fn commitment_binds_every_network_and_key_byte() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let key_bytes = [0xa7; 32];
        let key = SpendingKey::from_bytes(&key_bytes);
        let original = key.commitment(network).unwrap();

        for index in 0..64 {
            let mut changed = *network.as_bytes();
            changed[index] ^= 1;
            let commitment = key.commitment(NetworkId::from_bytes(changed)).unwrap();

            assert_ne!(commitment.as_bytes(), original.as_bytes());
        }

        for index in 0..32 {
            let mut changed = key_bytes;
            changed[index] ^= 1;
            let commitment = SpendingKey::from_bytes(&changed)
                .commitment(network)
                .unwrap();

            assert_ne!(commitment.as_bytes(), original.as_bytes());
        }

        assert_eq!(key.0, key_bytes);
        assert_eq!(
            key.commitment(network).unwrap().as_bytes(),
            original.as_bytes()
        );
    }

    /// Checks that the same parts cannot substitute a digest from another registered role.
    #[test]
    fn commitment_is_separate_from_other_hash_roles() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let key_bytes = [0xa7; 32];
        let commitment = SpendingKey::from_bytes(&key_bytes)
            .commitment(network)
            .unwrap();

        for domain in [Domain::RecipientKemKey, Domain::NoteEncryptionCore] {
            let other = poseidon2(domain, &[network.as_bytes(), &key_bytes]).unwrap();

            assert_ne!(commitment.as_bytes(), &other);
        }
    }
}
