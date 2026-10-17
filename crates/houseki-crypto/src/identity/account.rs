//! Network bound reward account identities for operational authority keys.

use crate::{CryptoFramingError, MlDsa87VerificationKey};
use houseki_types::{NetworkId, RewardAccountId};

impl MlDsa87VerificationKey {
    /// Derives the immutable account identifier for this operational authority under one network.
    ///
    /// The fixed Poseidon2 transcript binds the complete network, scheme 1 for ML-DSA-87 and
    /// all 2592 public key bytes, independently of balance and nonce.
    ///
    /// This establishes neither possession, registration, account state nor withdrawal authority.
    ///
    /// # Errors
    ///
    /// Returns the original framing failure without a digest, although input lengths are fixed.
    pub fn reward_account_id(
        &self,
        network: NetworkId,
    ) -> Result<RewardAccountId, CryptoFramingError> {
        let encoded = self.to_encoded();
        let digest = crate::hash::poseidon2(
            crate::domain::Domain::RewardAccountIdentity,
            &[network.as_bytes(), &1_u32.to_le_bytes(), encoded.as_bytes()],
        )?;

        Ok(RewardAccountId::from_bytes(digest))
    }
}

/// Independent account identity vectors and complete input binding.
#[cfg(test)]
mod tests {
    use crate::MlDsa87VerificationKey;
    use houseki_types::{EncodedMlDsa87PublicKey, NetworkId};

    /// Formats only public digests for independent known answer comparison.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Checks a complete account transcript with independent integer Poseidon2 and full input binding.
    #[test]
    fn account_identifiers_match_independent_vectors_and_bind_network_and_key() {
        let network = NetworkId::from_bytes([7; 64]);
        let encoded = EncodedMlDsa87PublicKey::from_bytes([14; 2592]);
        let key = MlDsa87VerificationKey::from_encoded(&encoded);
        let expected = key.reward_account_id(network).unwrap();

        assert_eq!(
            hex(expected.as_bytes()),
            "2deed4beb8cc9a66425049ef33a0e1639b43da6657810edea2885197800f9eff972f04a1e95b97fad1e1c9432474709bb3e355712b834ead7e239c5f1e5aee29"
        );

        for index in 0..64 {
            let mut bytes = [7; 64];
            bytes[index] ^= 1;

            assert_ne!(
                key.reward_account_id(NetworkId::from_bytes(bytes)).unwrap(),
                expected
            );
        }

        for index in [0, 31, 32, 33, 511, 1023, 2047, 2591] {
            let mut bytes = [14; 2592];
            bytes[index] ^= 1;
            let changed =
                MlDsa87VerificationKey::from_encoded(&EncodedMlDsa87PublicKey::from_bytes(bytes));

            assert_ne!(changed.reward_account_id(network).unwrap(), expected);
        }

        assert_eq!(key.to_encoded(), encoded);
        assert_eq!(key.reward_account_id(network).unwrap(), expected);
    }
}
