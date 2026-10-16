//! Fresh shared secrets encapsulated to validated ML-KEM-1024 public keys.

mod error;

pub use error::MlKem1024EncapsulationError;

use getrandom::{SysRng, rand_core::TryCryptoRng};
use houseki_types::EncodedMlKem1024Ciphertext;
use zeroize::Zeroizing;

use super::MlKem1024EncapsulationKey;
use crate::{MlKem1024SharedSecret, random::secret_bytes};

impl MlKem1024EncapsulationKey {
    /// Encapsulates a fresh shared secret to this validated public key.
    ///
    /// Each call obtains 32 fresh secret bytes from the system source and returns the public
    /// ciphertext followed by the protected shared secret for Houseki's suite KDF.
    ///
    /// The key's encoding was checked during construction, but encapsulation neither
    /// authenticates the recipient nor encrypts a note payload.
    ///
    /// # Errors
    ///
    /// Returns [`MlKem1024EncapsulationError::RandomnessUnavailable`] without either output if
    /// randomness acquisition fails, including after a partial write.
    pub fn encapsulate(
        &self,
    ) -> Result<(EncodedMlKem1024Ciphertext, MlKem1024SharedSecret), MlKem1024EncapsulationError>
    {
        self.encapsulate_with_rng(&mut SysRng)
    }

    /// Encapsulates using complete guarded randomness from the supplied source.
    ///
    /// Returns no ciphertext or secret if randomness acquisition fails.
    fn encapsulate_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(EncodedMlKem1024Ciphertext, MlKem1024SharedSecret), MlKem1024EncapsulationError>
    {
        let randomness = secret_bytes::<32, _>(rng)
            .map_err(|_| MlKem1024EncapsulationError::RandomnessUnavailable)?;

        // Acquire all fallible entropy before calling the deterministic backend.
        // Callers cannot supply this randomness through the public API.
        let (ciphertext, shared_key) = self.0.encapsulate_deterministic((&*randomness).into());
        let secret = MlKem1024SharedSecret::from_backend(Zeroizing::new(shared_key));

        Ok((
            EncodedMlKem1024Ciphertext::from_bytes(ciphertext.into()),
            secret,
        ))
    }
}

/// NIST encapsulation vectors and entropy failure handling.
#[cfg(test)]
mod tests {
    use getrandom::rand_core::{TryCryptoRng, TryRng};
    use houseki_types::EncodedMlKem1024PublicKey;

    use super::{MlKem1024EncapsulationError, MlKem1024EncapsulationKey};
    use crate::ml_kem_1024::shared_secret::tests::assert_secret_eq;

    // Public NIST ACVP fixture, ML-KEM-encapDecap-FIPS203, tgId 3, tcId 51.
    // https://github.com/usnistgov/ACVP-Server/tree/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0/gen-val/json-files/ML-KEM-encapDecap-FIPS203
    /// NIST public key for the encapsulation fixture.
    const ENCODED_KEY: &str = concat!(
        "f6690e77251a47a0126f3cae222b8873eb0ec9669aa7b08f4854aa72c0731649ce60eaa8b08198b8712158238dbe83ca",
        "efd7641434ce1a1346f6900a53c105462b4f1e909e680476000c8e8ff43dff9ac7f36657bf852262d383e68ca2c8764b",
        "59441523f009b5a752278491dbf89192fab92bc873ddfc5b5fb49f9160769bd228844127fddba4949a1ce958b6fc1388",
        "dee6cad9f549287b7e0c85300d636ac1a68c1f0860af00ce50963e3db200f651147c4425df62467fb4bfbd3b89da337a",
        "a74444409ba3fa73b8cd1454f7e7c730352f894387e79c7547c077c19496322817d3d540e496922f1063235b78ea66ba",
        "23918e79115277965e67760a2ffc91530aa85575474dc344f11130fc77ceec03adf4937fd7fbc838c05bf88263a9903b",
        "a10718b6c43e97047902827a491abfa8d83780191c96fc8924817fa3ab625c76132cea34273b3d74589e91114216989c",
        "8e98c5b4ec2e5aa01805bb598cb7137e61cb6907952a51ba54c52e9e8c629305b7982779d0cc9d43e14c254277a5124e",
        "06257cf7a61efc186118a808ce4ba0fcd31b34559d77643be90bd017b5c90c235615b61258d6432ee6138a90a0b3da38",
        "b6c8c20157644c010b6bbc327ac4b515e2ad5c46ad63ba0871946b6455a303448662a1cbccba1a462389b7ea4aafd4a4",
        "11e2a45d92146fe4508094c8e4f2747e918a2e57874c934a5c654f137695c67084a3ec50f3e7c777dc42aac0aa972701",
        "5546cae376c68504aa99a8ae585c2be6e84e510124b5ea9169c356be0239cd8c900da93203716c3557bab802c846c319",
        "48b7b2eb064e2de01e9fca837d4986e43a019bd351dce5218fc1386a46684f2347f6ea999c07586ae66da4a129fe3c36",
        "e1435b0715b155477000768ef7877c618579ccd958dcf74323e9c065a04f0f1b23ace41b0faa69dfd53ea2c62af467b0",
        "df64800e79c4fe72419958ab1d470250b5122a915eb00a44f4545dc83b78a0942702b71d9339115e007fab9684fb3880",
        "b0e97221d5867d4cb0a4921fa29a81a939231f2c1cc5d329652052c3484602316b792abcd55036e1f41fdee702ba1216",
        "ab71918f469503ec85e9321ab8d4287bd537194560e1f140fe3900d1864f588b4aac648d1647612837cd11ec6b730768",
        "528a96d825bd06033a4734b04b2aa6f26586a345605e59781f046738c51747564183b139e772b94194b3eb64407c462d",
        "c54c14cfc81bab301f9091950b5a97bff836990c0a419ab1c8f08a8d200aa3b968a19224e03b140c998a58b86221cc25",
        "8c407f0dda752a890d58425d6269b4cb03052da31cd0ecb04b36a42d30a1edf98570a31ceaa81ec9382f6dc012f63728",
        "f38a5983b50df7c65491934f2cbb9cdd714284c0706ff79bb1f879b6ea423c71198bfa0afb628469bb0e6f79c174463f",
        "dda6ba4a78a886ec690fda63cd93b66cb01e384395fe0281a7dcb55661b2dfaa7990cc19beb96bcc29740f305ff3c722",
        "81a5991f3b39135b066389c1dab7b0a2babbeee76bd99b394c82a28ebb275643c288e421bffc94ab317dd5191220e952",
        "7549670c67aa4d26ce8a6aa1c8629601631b35fb9fb881c1ff03ca68c2be4d913269274b04668305a6ace7129654c51d",
        "c9c78ea9b07b489241a0e4c83fd5b2857a13ab4aa9d7139202ac08e2877624d07aee9c6954dc7e0ba693f260b714b80c",
        "92f6b411d510e6276061451d99e54ad55954993b9624fab31debb0ff700b10fa3d7c3952e48082f4d87ddb703e55cb65",
        "577450a375c56644501364b871766ddfe57cefa187745ca3b6f87890c2ac65b89ddbb9ae7af90f9baaa353043cd382a4",
        "089c5744d11e78d71a61d01f4c345c5caa9b385c7af35a72545c677bcb363b129a0392033956064fc199cff4baafd03a",
        "3413c65b025fc186475690ae93699db6d0b71b285aba96201d149968574613865cfa26cfeae7c249fa5d5fb18480a752",
        "c368681a5969aee20da1f0acce6281852441862b1b4c01a1c0352211d49204a46701f72c52287e4c8a8ffd8668e02273",
        "29e84b1e0a8d47418a4af44a6e80cba470a4a04c1817156a87f4ab7055389ab3b51dec6cd64cb8d7890b2d4bb85e4ab2",
        "0ac3aca6762b0100640f92040be73906e68e8103a57669532120312fe50ddd47ac0b19151fd6137b16a09324948629b8",
        "4fa2e7c8ec150fb8c7db1d800c0825ac18915be2529771b8390945e6da65f324",
    );

    /// NIST encapsulation randomness for the fixed ciphertext vector.
    const RANDOMNESS: &str = "bf233cf6121d41585b4af0ea74b35df7ed52bb5782107a8259cd4aecc3587e61";

    /// Complete NIST encapsulation ciphertext for the fixture.
    const CIPHERTEXT: &str = concat!(
        "efdb7f7e56302a199a7be79c00715f670a5024c0fd357bfd446b4a9371079c5a04964f5f4d0c8fb3d12ad1f6f2007d26",
        "f698c49da91e3b107d2332c7612df3d7a216fe4f07c5ad8a1e9e2de80e3ed3b79bdba3e5388fbda4311f79401798d193",
        "082b17692bfe3286ca442c5f7d4d63327cf40d7b0c420084c636a283e83483a469cf88e669129cf868f013f8796fd76a",
        "e474ed75af8832bf0a3658a4edb3fd2f37dca44586c78728834226e5ded1732a2b3ed1c0dbf4a825818c344cfd60d4db",
        "460e2e5b2b1931500dd22c098cf45f407d73cb04e83ca866090c244a11d08613ba174b06f7c58633bc01629be2f41a69",
        "5e8f9ad2e09c2bab4ed34aaca0303b58f3b3e55d16f4a84b4bcdc6d7c4c20170db0dd0fd20f4b7fcf8e6df8c7bbb7507",
        "5eea2ba10eafc071a83df4b2401cadd328fb729cc5071c1c869deacc3fcd8b60fb157b1c424491d3ab36dfe8d15cf3da",
        "de14a109a014d157cae91f1f7fee9cafac003f2a6fa9f3e4c6960299c71bdfc168770a7d034ff52120599ca005886ee9",
        "7fd4f15af42ba209052a6a93069cdccd91a380156a0ce7bca73851d37b916c1c93f5a45ab48df44dd2b1d6b23c91de70",
        "f480c397b4c05a8b93e199d4ef247be533fced03ccef20d313e2fe313967e4f4de65817710d4c6947ff06a9508777712",
        "f4c66987883bcba57509c588e8a71c3a8c7d70cf50a945da7ba742b16cfa756856127e04d0ae0e82cbb39ae7adfb8a68",
        "8abf811d08928eea3304753596ba04471b8e3ca5f330e98cd3cd9ee6ebe9a12b9d58445894d5a5c1846bdb20d322545a",
        "cec6972e829cf671b81b79fc0b140ec5940db91c479c46b7e92572d8a77064784422e04e273375afab75982f6444092a",
        "2bc507097bdc84312c27f72158f70c3679fbed151796e8086825b15287857e19640459119732fb4469415b96db7da854",
        "62c2d269174bc7bf4d4b992d0b6a4da92baa2be7f88ad0ac06bfbed1a5854f8348baf9946728cbb42bb61fa288c80f07",
        "cfe669f9617747c975c835ea476c4e8ff288f65ba82f50af0b9e9340960bae41c6a6a6faad0fa15785a2cb77cd67afe4",
        "88902c1db7fb2eab64e1657db282533dc909ccaa267a16502e0025a8b4c45bb6bfab262e67b388fc62530950d93699ff",
        "078d21c9621b4937cdaeb45858959d64999f393be59e8304dfa079663b9b6e126966f6dd39c54aa193c9dd8785ec4e5c",
        "13858e2914decc4153c99b1ad8b8211c1dfe35858cf9736a4ca5b259d0b1aa528d52181dfe54061d960c939f6be3ec1e",
        "8bea3b9ad579b1ec13d4cc7fdc3166ae370c49d45ffa4ad483db3071865007e2dd079518a2fa738dcfd94d79d36af57c",
        "2df26ac4df777579e18db9c107cb0022d0249d2bdb7b4503cb374e4a1a59061f05cf0ec6020ac0fa1965ada850caa5b8",
        "9822e0ff50ac8afa464b73e7cb8bfde7ca305245e867abbb35d3e4086e64355922b977cbdaecd0cdf272506a50f2e1d9",
        "7e8db39c6443f76a0d7ea0b4e19ebe7eef0851c45714b59f74171114d2d5d589da46e4d5de7b83c484531ab0d4b76b78",
        "6ce7ca99a22fc70f8ca901579e38cdf7443b44b4cccc70c901ec3fe034b64c78f6b12cb5426e74724eaa75289fddccdc",
        "653d998a3a00c8c64cb47b5814130aacbad79f55b14a0ef81e440d4e2fe1c8eb4d8888faec6898e23aee45b4b8f6e5e6",
        "4cbc38e498d57034dec3f2d44426824635cc624a4b49bdd745bc52b1f151c193ca6855778fef4f39e72c576daeda9f60",
        "41682aa1bbb2f134218028ddfc82589a2179a9ab70ecf613593ea6e04a47e83dd88235578610206cf6034159f3765302",
        "66a461faf89a6363269f6ea266f9a406e852f3b2081f1d36b6ca41d2dc0c4c644e4263ae36ee79081b352700a2d1c7a7",
        "badc4ba24291271cf4ad3a02a8789d25e16f9e3755e2f61d9f018d79d4c7f2e5fd640e738ce055535fdcff651b2fe703",
        "44168619bfbdb1f5acf0222fd689070d0ad758c11d485121ecc0d2d04b1d91fdbe8b1f315f991cec0e5cd0ee3065b0bb",
        "3d9627677a7d4d4ca0d539e7552d6b2d89758d8ec4a9afe41c1fd896d4912f71cba5e49f550118eabd0c67497c162f42",
        "052c4a6aa4009e2a210c5d4a3ae2165dc44d5072123354c542c80e57f86bfec55500181c7e057d1884047a5e6815a954",
        "5b642bd631c5a46579a507253ffafec18581381d50fe491d319a1ab4a0d19689",
    );

    /// NIST shared secret for the fixed encapsulation vector.
    const SHARED_SECRET: &str = "bcf2efed1e45c35c5fafe170aac3f4f5b3ef11220ea6b9a254f0b90ee8d56b94";

    /// Decodes a fixed length hexadecimal conformance fixture.
    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }

    /// Imports the public key from the published encapsulation fixture.
    fn fixture_key() -> MlKem1024EncapsulationKey {
        let encoded = EncodedMlKem1024PublicKey::from_bytes(decode_hex(ENCODED_KEY));
        MlKem1024EncapsulationKey::try_from(&encoded).unwrap()
    }

    /// Checks both encapsulation outputs against the NIST vector.
    #[test]
    fn encapsulation_matches_nist_ciphertext_and_shared_secret() {
        let mut rng = FixtureRng {
            position: 0,
            fail_after: None,
        };

        let (ciphertext, secret) = fixture_key().encapsulate_with_rng(&mut rng).unwrap();

        assert_eq!(ciphertext.as_bytes(), &decode_hex::<1568>(CIPHERTEXT));
        assert_secret_eq(&secret, &decode_hex(SHARED_SECRET));
    }

    /// Checks encapsulation failure after a partial entropy write.
    #[test]
    fn encapsulation_returns_no_result_when_randomness_fails() {
        for fail_after in [0, 16, 31, 32] {
            let mut rng = FixtureRng {
                position: 0,
                fail_after: Some(fail_after),
            };

            assert!(matches!(
                fixture_key().encapsulate_with_rng(&mut rng),
                Err(MlKem1024EncapsulationError::RandomnessUnavailable)
            ));
        }
    }

    /// Checks repeated system encapsulations produce distinct ciphertexts.
    #[test]
    fn each_system_encapsulation_uses_fresh_randomness() {
        let key = fixture_key();

        let (first, _) = key.encapsulate().unwrap();
        let (second, _) = key.encapsulate().unwrap();

        assert_ne!(first, second);
    }

    /// Deterministic entropy source with injectable partial failure.
    struct FixtureRng {
        /// Offset of the next byte in the deterministic entropy fixture.
        position: usize,

        /// Optional byte count at which the source reports failure.
        fail_after: Option<usize>,
    }

    // Deterministic and deliberately insecure.
    // This implementation is test-only.
    impl TryCryptoRng for FixtureRng {}

    impl TryRng for FixtureRng {
        /// Error returned by the fixture entropy source.
        type Error = std::io::Error;

        /// Reads four fixture bytes as a little endian integer.
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        /// Reads eight fixture bytes as a little endian integer.
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        /// Writes fixture entropy and optionally fails after a partial write.
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            let randomness = decode_hex::<32>(RANDOMNESS);
            for byte in output {
                if self.position == self.fail_after.unwrap_or(randomness.len()) {
                    return Err(std::io::Error::other("fixture entropy exhausted"));
                }
                *byte = randomness[self.position];
                self.position += 1;
            }
            if self.fail_after == Some(self.position) {
                return Err(std::io::Error::other(
                    "fixture entropy failed after writing",
                ));
            }
            Ok(())
        }
    }
}
