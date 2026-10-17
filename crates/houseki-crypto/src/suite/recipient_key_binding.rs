//! Recipient key binding under a fixed network and suite.

use super::CryptoSuite;
use crate::{CryptoFramingError, MlKem1024EncapsulationKey, domain::Domain, hash::poseidon2};
use houseki_types::NetworkId;

impl CryptoSuite {
    /// Derives the 64 byte recipient key binding used by the note relation.
    ///
    /// The `houseki/v1/recipient/kem-key` frame contains the network's 64 bytes, this suite's
    /// four little endian identifier bytes and all 1568 validated public key bytes as separate
    /// parts.
    ///
    /// Its byte length is prefixed as a little endian u64 before seven byte packing and field
    /// padding feed the fixed Goldilocks Poseidon2 width 16 profile with eight full rounds, 22
    /// partial rounds, rate seven and capacity nine.
    ///
    /// Eleven squeezed elements form a canonical base p integer whose low 512 bits become the
    /// little endian output, rather than serializing eight field elements.
    ///
    /// The resulting output space and negligible extraction bias under ideal uniform field
    /// samples do not establish 256 bit security or a quantum bound.
    ///
    /// This public input operation binds the supplied values without establishing recipient
    /// identity, private key possession, note agreement or ciphertext authentication.
    ///
    /// The binding need not be published with an encrypted output, and this interface accepts
    /// no secret hash inputs.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoFramingError`] if the transcript cannot be represented or completed,
    /// although all inputs in the current suite have fixed lengths.
    pub fn recipient_key_binding(
        &self,
        network: NetworkId,
        key: &MlKem1024EncapsulationKey,
    ) -> Result<[u8; 64], CryptoFramingError> {
        match self {
            Self::V1 => {
                let encoded_key = key.to_encoded();

                poseidon2(
                    Domain::RecipientKemKey,
                    &[
                        network.as_bytes(),
                        &self.id().value().to_le_bytes(),
                        encoded_key.as_bytes(),
                    ],
                )
            }
        }
    }
}

/// Independent recipient binding vectors and complete key coverage.
#[cfg(test)]
mod tests {
    use super::{CryptoSuite, MlKem1024EncapsulationKey, NetworkId};
    use houseki_types::EncodedMlKem1024PublicKey;

    /// Constructs a canonical public key fixture with the supplied matrix seed.
    fn key(seed_byte: u8) -> MlKem1024EncapsulationKey {
        let mut bytes = [0; 1568];
        bytes[1536..].fill(seed_byte);

        MlKem1024EncapsulationKey::try_from(&EncodedMlKem1024PublicKey::from_bytes(bytes)).unwrap()
    }

    /// Checks recipient binding against independent complete profile vectors.
    #[test]
    fn recipient_bindings_match_independent_complete_profile_vectors() {
        let network = NetworkId::from_bytes(std::array::from_fn(|i| u8::try_from(i).unwrap()));
        // Independent Python profile oracle, with canonical zero polynomial coefficients and
        // unrestricted public matrix seed bytes.
        // These are Houseki encoding vectors, not claims of honest key generation.
        for (seed_byte, expected) in [
            (
                0,
                "f001ec9a7577a1366a3f0742913a65fa1530446a8df7c9db52896d0459b514acfdbe01363ce585fb1473cf32a9ba8602a235e57a0f5f016f95d7c157590a7b7c",
            ),
            (
                255,
                "9e299d404d652227b2da6416279f8dfcfc40082de26259aaf6ad8e97803e4301db18de1923f8cce234521ff67c7dd3a70bf333aba8dd2a8430520557c9a6c8ef",
            ),
        ] {
            let digest = CryptoSuite::V1
                .recipient_key_binding(network, &key(seed_byte))
                .unwrap();
            let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();

            assert_eq!(actual, expected);
        }
    }

    /// Checks complete network and public key coverage in the binding.
    #[test]
    fn binding_covers_the_network_and_complete_key_encoding() {
        let network = NetworkId::from_bytes([1; 64]);
        let key = key(0);
        let original = CryptoSuite::V1
            .recipient_key_binding(network, &key)
            .unwrap();

        for index in [0, 63] {
            let mut bytes = *network.as_bytes();
            bytes[index] ^= 1;

            assert_ne!(
                CryptoSuite::V1
                    .recipient_key_binding(NetworkId::from_bytes(bytes), &key)
                    .unwrap(),
                original
            );
        }

        for index in [0, 384, 768, 1152, 1535, 1536, 1567] {
            let mut bytes = *key.to_encoded().as_bytes();
            bytes[index] = 1;

            let changed =
                MlKem1024EncapsulationKey::try_from(&EncodedMlKem1024PublicKey::from_bytes(bytes))
                    .unwrap();

            assert_ne!(
                CryptoSuite::V1
                    .recipient_key_binding(network, &changed)
                    .unwrap(),
                original
            );
        }
    }
}
