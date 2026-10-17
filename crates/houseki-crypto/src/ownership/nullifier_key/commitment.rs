//! Internal nullifier key commitments for the ownership relation.

use houseki_types::NetworkId;

use super::NullifierKey;
use crate::{CryptoFramingError, domain::Domain, hash::poseidon2_secret};

/// The public digest binding one nullifier secret to its network and cryptographic role.
///
/// Construction requires a nullifier key, while the digest cannot replace that secret in
/// note nullifier derivation or establish spending authority.
pub(crate) struct NullifierKeyCommitment(
    /// Complete derived digest in the profile's little endian output encoding.
    [u8; 64],
);

impl NullifierKeyCommitment {
    /// Borrows the complete public digest for composition into the ownership commitment.
    pub(crate) fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl NullifierKey {
    /// Derives the internal nullifier key commitment under the supplied network.
    ///
    /// The `houseki/v1/ownership/nullifier-key` transcript contains the network's 64 bytes
    /// followed by this key's 32 bytes as separate parts, using the guarded Poseidon2 profile.
    ///
    /// Only the resulting public digest leaves guarded storage, and the key remains available
    /// for later nullifier operations without exposing its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoFramingError`] if framing cannot be represented or completed, although
    /// both parts currently have fixed lengths.
    pub(crate) fn commitment(
        &self,
        network: NetworkId,
    ) -> Result<NullifierKeyCommitment, CryptoFramingError> {
        let digest = poseidon2_secret(
            Domain::NullifierKeyCommitment,
            &[network.as_bytes(), &self.0],
        )?;

        Ok(NullifierKeyCommitment(*digest))
    }
}

/// Independent commitment vectors, complete input coverage and role separation.
#[cfg(test)]
mod tests {
    use super::{NetworkId, NullifierKey};
    use crate::{SpendingKey, domain::Domain, hash::poseidon2};

    /// Checks the exact domain, part order and complete hash profile against integer vectors.
    #[test]
    fn nullifier_key_commitments_match_independent_vectors() {
        // Independent Python integer arithmetic with the pinned public constants evaluates
        // the explicit frame, full matrix products and modular powers before extraction.
        for (network, key, expected) in [
            (
                [0; 64],
                [0; 32],
                concat!(
                    "163a7706a8455fd5dbd410d3011524184fbeab1995ca0676b6438aab351255eff",
                    "5a3dc146a6b9e3d48488bf4086c726114a8932906a03928047cbb510270a946"
                ),
            ),
            (
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                std::array::from_fn(|i| u8::try_from(i).unwrap()),
                concat!(
                    "4d2295d8e0f92056088cc057791bbc112c86b6c2bfa4bd168c02f9977055ed17b",
                    "a2f7e4a7d471c0c96cca5031061307546e0aed03dea17790ec8d664ad7a928a"
                ),
            ),
            (
                [0xff; 64],
                [0xff; 32],
                concat!(
                    "515a3f66ff7d9ceb47a8df21d3d7939851d5bfd154fdda88f7b7b42fbc48540a6",
                    "aad3360b1f16c83f39380347c18252042f05e781b62b22b5ade0b2058b73c6b"
                ),
            ),
        ] {
            let key = NullifierKey::from_bytes(&key);
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
        let key = NullifierKey::from_bytes(&key_bytes);
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
            let commitment = NullifierKey::from_bytes(&changed)
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

    /// Checks separation from spending commitments even when public fixtures reuse key bytes.
    #[test]
    fn commitment_is_separate_from_spending_and_other_hash_roles() {
        let network = NetworkId::from_bytes([0x35; 64]);
        let key_bytes = [0xa7; 32];
        let commitment = NullifierKey::from_bytes(&key_bytes)
            .commitment(network)
            .unwrap();
        let spending = SpendingKey::from_bytes(&key_bytes)
            .commitment(network)
            .unwrap();

        assert_ne!(commitment.as_bytes(), spending.as_bytes());

        for domain in [Domain::RecipientKemKey, Domain::NoteEncryptionCore] {
            let other = poseidon2(domain, &[network.as_bytes(), &key_bytes]).unwrap();

            assert_ne!(commitment.as_bytes(), &other);
        }
    }
}
