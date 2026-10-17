//! Protected private decapsulation keys for ML-KEM-1024.

mod decapsulation;
mod error;

pub use error::MlKem1024DecapsulationKeyError;

use super::MlKem1024EncapsulationKey;
use crate::random::secret_bytes;
use getrandom::{SysRng, rand_core::TryCryptoRng};
use ml_kem::{KeyInit, ml_kem_1024::DecapsulationKey};
use std::fmt;

/// An ML-KEM-1024 private decapsulation key and its matching public key.
///
/// Create a fresh key with [`Self::generate`] or restore an existing secret seed with
/// [`Self::from_seed`].
///
/// The resulting key keeps private bytes internal, redacts debug output and provides no
/// cloning, equality or serialization.
///
/// The backend zeroizes stored private material on drop, and temporary generation seeds are
/// cleared on success, error or unwinding.
///
/// This cleanup excludes the caller's imported seed and cannot erase every copy made by the
/// compiler or operating system.
pub struct MlKem1024DecapsulationKey(
    /// Backend private key with its matching public key and drop cleanup.
    DecapsulationKey,
);

impl MlKem1024DecapsulationKey {
    /// The number of secret seed bytes, comprising 32 bytes of d followed by 32 of z.
    pub const SEED_LENGTH: usize = 64;

    /// Generates a fresh key using the system's cryptographic random source.
    ///
    /// # Errors
    ///
    /// Returns [`MlKem1024DecapsulationKeyError::RandomnessUnavailable`] if the source cannot
    /// supply all 64 seed bytes.
    ///
    /// No key is returned on failure.
    pub fn generate() -> Result<Self, MlKem1024DecapsulationKeyError> {
        Self::generate_with_rng(&mut SysRng)
    }

    /// Restores a key from the secret seed format in FIPS 203 Section 3.3.
    ///
    /// The seed consists of d followed by z, each originally sampled independently as 32
    /// uniformly random bytes with a 256 bit security strength.
    ///
    /// Because every 64 byte value can be expanded, import cannot establish entropy or
    /// provenance and must not be used with a password, public matrix seed or expanded key
    /// encoding.
    ///
    /// Use [`Self::generate`] to obtain a fresh key with the required randomness.
    ///
    /// The key retains no reference to the borrowed seed, whose storage remains the caller's
    /// responsibility to clear.
    pub fn from_seed(seed: &[u8; Self::SEED_LENGTH]) -> Self {
        Self(DecapsulationKey::new(seed.into()))
    }

    /// Returns an owned copy of the matching validated public encapsulation key.
    pub fn encapsulation_key(&self) -> MlKem1024EncapsulationKey {
        MlKem1024EncapsulationKey::from_backend(self.0.encapsulation_key().clone())
    }

    /// Generates a key from a complete guarded seed supplied by the given source.
    ///
    /// Returns a randomness error without a key if any seed byte cannot be obtained.
    fn generate_with_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<Self, MlKem1024DecapsulationKeyError> {
        let seed = secret_bytes::<{ Self::SEED_LENGTH }, _>(rng)
            .map_err(|_| MlKem1024DecapsulationKeyError::RandomnessUnavailable)?;
        Ok(Self::from_seed(&seed))
    }
}

impl fmt::Debug for MlKem1024DecapsulationKey {
    /// Formats a fixed redacted label without inspecting private key bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MlKem1024DecapsulationKey([REDACTED])")
    }
}

/// Seed conformance, entropy failures and private key redaction.
#[cfg(test)]
mod tests {
    use std::fmt;

    use getrandom::rand_core::{TryCryptoRng, TryRng};

    use super::{MlKem1024DecapsulationKey, MlKem1024DecapsulationKeyError};
    use crate::MlKem1024EncapsulationKey;

    // Public NIST ACVP fixture, ML-KEM-keyGen-FIPS203, tgId 3, tcId 51.
    // https://github.com/usnistgov/ACVP-Server/tree/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0/gen-val/json-files/ML-KEM-keyGen-FIPS203
    // Seed order is d || z.
    // The expanded key is used only as a test oracle.
    /// NIST private seed encoded as d followed by z.
    const SEED: &str = "f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e726600935d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275";

    /// Complete NIST expanded private key for the seed fixture.
    const EXPANDED_KEY: &str = concat!(
        "6cbbb491d7b3a3439f53c9027bd727a0e1c78004b4cdb66760e50f1bf97fff0139f82862f1f3178a077b6af77735cb80",
        "2e91316bc207b9f1485ff7a868891e003bb9c6558be6052c0826af1cb5836b94c7d5d714eefc7cfd983e9884b7134849",
        "9dca05def33b49d1c14bbbb95ab195bd72219b18bd0c704275cc94ab06653bbb9e0eec74181903a0081aae068b81ebae",
        "8925335b8134b1480a60f758282c2f011b909641266774513a19090bc672eb3a0708cb577f134151c155c1e560d9b335",
        "a35a4d75f223502752cd250c9a7778efc76a52709813a24679b987a6172f1714641ea6902d364f96357e92b44275ebcc",
        "e7f6207bb0a215e98b3aa92daa46a39ad9132f3874c6239391e716ba600e42bc7084425051f865756a89dab46a76104e",
        "183a12031b99be86257b583c2e88104fec3bfcaa50f238beec20abf31219685885f2c3ce2f80c09b874e73a8712d35b8",
        "ee819d84b1c59a37947c0b9e25f066ee030ed28172fd5914b562408ba9b9de9bab2b95a4f30c22ece458e133371a693d",
        "9458058265a75ad6ca5707617b38a1b6f396fb199cc1c77100741de37500f1bbb10b9204eeb7c3f5b91a1cc91b6d4072",
        "af410957358acb0625488b9f6a9915758b7cc9b4afe7d5ad6a95231a7a711b3a8996e23afb3695b45b6d919c771d7685",
        "d90a7550a9b5b1e7538a365451a5a815009e49326c6541caf0ba685056bf82ea4ab504161b555568583802800554a948",
        "0602437b0b9677fac638a2508154a658e0623c62666e078d21a5a545a818d66c9547b9749458b735a4ad51812950e8a6",
        "25a1b2a753abbba16415006300ad32d34c8b0b3b2af4d1cfbde08b4f06c70de4ba28fb3763745cce133dd2e488f89a51",
        "e7a586a86ac928867b0541438af5645de3211aa94aca4a1095896ebc363c374a85565c1eba030b5ea21b9b8a140e131e",
        "d07580d5b8590446988da65939a823a84661b26ca12461afe373519f43c13987a96a9069cd6b9177b205b25b5197dbcd",
        "e66c6457892c1df96fe50ab7ef3b3dab0a87436b3451476c44aa22aef918ae5a1a8ae46920263032e3bc5debcfee43b8",
        "aa290cedf06966939ee6cc7c6af83cb9d90cc889ab8b5a3d4c224e73916ae057bf5455528cacbed31b554043c6b0ea19",
        "6854461d2644461470efc55080e326fed49d62b5a4bb06b14f505eb4486c9a1b033b927836da656c2475e5b8b823986d",
        "ca99b298512d94b77fe0588dbb96ba53a67369b82c2beab2ccc0103e549317a99dd97b598fa0a506184eb55c96b17302",
        "533c7ec3334e3cec2bbb22be0f89442840884fab4a766a41bc8061d4abcac5190c729309ac6151bd434b818bc1e7d0cd",
        "435c9ca6dc7182228ff93867134a5cc65c6167c4a8bb830e7feb863c15bf87b259eb0518ff5248792a625f37c5895897",
        "99746d36197dc63aabd134a00ef1b49c79a2df67b28e6b6e989cc9d0577ea5aa1b2fe64b322c7a8b241d503523d875cc",
        "dc479d28e3c01bd8383dcb2b684281e6949171f518ea97009237b5cd42ac8fc8a571716eb784b336529db67728499988",
        "b73b80ef5c6d33f3b42ada7a0a36a7c6a8a0dfb804b3d7bb05803957b913827a16f52acdd7650ee2971a85dc21f6a94a",
        "5b31988e4438a9c1733ab8c48c32653fe800bf81ba66658cd2001acf3a83e3a0426ab6c3b2600a53621277a43d723ab9",
        "6758b120f120248c15edf4294fc38f96ec490bd52094655841d9355038a379d8b666875171f39218e21d37023f5108b6",
        "d15389f07c1241e15071c43cd7d160eb5341b719c2055424ef6cbf66815f84943c9481cd1de685a74c5b9db37a071395",
        "2fd4a67bec8ca7496f6c9c5fb84a8eafe68d54654c6bac9c3ab712c2bc32c0cab072c18de3cabbd9224dfaa305dfdb3f",
        "85019d7b988577b40f27514822db42d87489502c53cce6a095b486d9143d6d160b1c7313bf288913657698117eb145c0",
        "c9c55d66c15bf1a2b268f6a5fa259139551abfe3468f1cc49c01b4232543def0bf9ae503b998536310751a8bc302b4b4",
        "440b835233797c967e7f9308155b27ba63c65e08bdd1946828196b30c042cda0b56e4008215ac51f373604f5930bb662",
        "97c32be41a162ca21471cc86657b5cb5307d89091da9a5137f1c1433ab8ac1d59de421c7c17a883eab99ba4714f84199",
        "8d0923ca8a2da2b4146ec25321122b8a5aa8afe0c03415273008a46ee83031e98aaaa125abc75d3b30322560c197e75d",
        "d0e48a348099f7b2144d7b8a8660a4a97bcf19c0583bd9bb2123033cd7bb5a14b08b817831a673a28170f5f6443c0551",
        "913a327cba18c3a053c4040250403b70ab9588832403aa0fc37665e04980fe1602e7d2715d9cbc00515df432a4f5b32b",
        "3bc92ae3f31700166d498123e94576509b712b18491b1435ee7ab7aeb1ad30d72348c3cc083abe24a8b12097bf32f792",
        "476288eecc3bf630adcdac6aca7950d9839501a448500742bae37f109203a809b2b960a307e25347a32c3eab79288173",
        "a878789b296e9e8c1c28c5bb3ac472601c9765f7b77225a810c7b85370bef4a5b079d2015ada54236b8f33840675f9b2",
        "eb427a1b5974cd5c61b24010886c5a7bda5bbed974af7217f3338ad719cb308a8bcb1b6d6ed2a1643736c29095e8a845",
        "2a3a36c7bb5ae58cbfdc61529466a90f454ed6895b0861083dd1371999b2f559a3a487cf59a074fb49215ea6a6be656f",
        "9af17b121a2447cb7985590e9738842b899ba57ac311810ae2d9794f37483dd6bccb64af6d56588ae94665961c025c3a",
        "a2861974c236bca4bd8ff5509f7ab774593e7c5549e57c2f18d15c0515094ad9a0dfaa0601e524f8231156b627bb25a0",
        "dae04dacd0a66c041cef400583fc13bae640291a39a5c5ca8bca1ad5c683cdd8290891a76940817dd8c9f52678780548",
        "e37a05806600801426dbb950c3b2ba34e24cc77864dd91b39f1408c716a69df63342854e50a245fb50977b9410ded2c9",
        "3f86b1f9d5a78b87bf81e51ca620a7e8566b19ab700964a40e3266415228d432156e5cbdf52364a90483a55c39b3fb16",
        "fc7465a3f8ac801b70b9fb28b583444ba5c1a73722d417a9d6d9b7deb08bc6b330ff27cf61ab8831e27758c64af3b121",
        "50cb7b33abc29858106d63686d8762459abf9413850ae53ed6313f76f83d0fb8ab34374e7df693e4a1b3e5a8ad0ce820",
        "afe1cf401acde650a8101b0946022d52178e19613c42b88b07cc04eaa81dfb28ac9dc076236b67219a30f8f945dd57bd",
        "2f335c52d59372308d38993467db53da3382b74867b616481bd0091a2232c1116dc88a589db9107224a681008c67c589",
        "186a6929549beef92253db02b0c8aa9f9c875a670266c72bcbdb4f5625043703c1a0457395832e4c335180462ed2220c",
        "59e7361903c107d85457f6cd82eb820d0855d97675c2e0151cdb73c2885ddb7849d74541580124e890116a65bc068093",
        "b57914e20c937c60a3eb25576f1a976a9583839b672144cd4a45c3477a45c29b4e0bc2bdbd206585c9b7a7741c8b6b57",
        "93a92797a15ae7a5b73a74b2971463634ba52aa792af05530730b6d0a89a346156b733677932bd36593a7496130cc458",
        "dcc5ca987c21960604ec8a8c5396056680cbf3f1aac4f401aa5029fb2150434bb4706c31a2d54e4297939fa7c9c6f857",
        "00613ceb65c7f03ac56eb86e2d27ccc6dcb7b9394dcdb942ff222d86958a996c0cb6a8a44f97a70441c95fa71250116e",
        "ec20863c0b5a643458788ab001f8869d909922f51ee547a1e889255b3a0599c65842e5ab8d73872f053bc62392ea5389",
        "6d328102d460bf1609583c22c3b43780ec6dad0319eb4a5a65b4756c3cb40eaa935183bf8bd46abe76ba46e199103a53",
        "13c3235f49c915e097bca804de680781d8365731beac6789a9203fb8787c4c070e00a13a6722a66a28236db179825653",
        "d33ccf898b72c6b8450d97afd3276bb13340519cbeda708d12a858f54c49f4547195b7788a9150b2649e36aa39412192",
        "6d568a488b16d3557b2a32af57d11fc3373f80a28c0723273d362502e7c428ab44d3cbabf9ea585fd1bd0c9846556a1e",
        "196b78cf951592984a0a8487a78c2317d7aca4118e1049750a0788f0d66ad9e48e34731130aba0b427360a856d96d80b",
        "3f028fdd3aba9035c10106ba1c0934bed36c6d7c7434249654ea89fc22137f4ab903653b75fb25b6f01635e6cc7d39cf",
        "1508690562826b49b6ffc59e0dd35022e541f8ba0d304aa5b4e20606907c424395666c54abc2b8fb009847c863176850",
        "00c231215c8c15945860f6a85ddb98a8c3a527f2749d3c027e694e8f0b0f0fa454913aadb635aadd452f7128bf775256",
        "9669a8b93290eb92e78f6adff23e89f57f3890753b51f12f3f3a8a654e6778479370fe5b05ddc92c939f62cbde4c0fea",
        "36f45cd20c5748cf3ac891a4c260449635d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275",
    );

    /// Decodes a fixed length hexadecimal conformance fixture.
    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }

    /// Compares the complete generated key with its published NIST fixture.
    fn assert_matches_nist_key(key: &MlKem1024DecapsulationKey) {
        // The public API intentionally offers no private key export.
        #[allow(deprecated)]
        {
            use ml_kem::ExpandedKeyEncoding;
            let actual: [u8; 3168] = key.0.to_expanded_bytes().into();
            assert_eq!(actual, decode_hex::<3168>(EXPANDED_KEY));
        }
        let expected = decode_hex::<3168>(EXPANDED_KEY);
        assert_eq!(
            key.encapsulation_key().to_encoded().as_bytes().as_slice(),
            &expected[1536..3104]
        );
    }

    /// Checks the complete expanded key against the NIST seed vector.
    #[test]
    fn seed_import_matches_the_complete_nist_key_generation_vector() {
        let key = MlKem1024DecapsulationKey::from_seed(&decode_hex(SEED));

        assert_matches_nist_key(&key);
    }

    /// Checks consumption of the full seed in its prescribed order.
    #[test]
    fn generation_uses_all_random_seed_bytes_in_the_prescribed_order() {
        let mut rng = FixtureRng {
            position: 0,
            fail_after: None,
        };

        let key = MlKem1024DecapsulationKey::generate_with_rng(&mut rng).unwrap();

        assert_matches_nist_key(&key);
    }

    /// Checks key generation failure after a partial entropy write.
    #[test]
    fn generation_returns_an_error_even_after_randomness_was_partially_written() {
        for fail_after in [0, 32, 63] {
            let mut rng = FixtureRng {
                position: 0,
                fail_after: Some(fail_after),
            };

            assert!(matches!(
                MlKem1024DecapsulationKey::generate_with_rng(&mut rng),
                Err(MlKem1024DecapsulationKeyError::RandomnessUnavailable)
            ));
        }
    }

    /// Checks fresh system generation produces distinct validated public keys.
    #[test]
    fn system_generation_produces_distinct_valid_public_keys() {
        let first = MlKem1024DecapsulationKey::generate()
            .unwrap()
            .encapsulation_key();
        let second = MlKem1024DecapsulationKey::generate()
            .unwrap()
            .encapsulation_key();

        assert_ne!(first, second);
        for key in [first, second] {
            assert_eq!(
                MlKem1024EncapsulationKey::try_from(&key.to_encoded()).unwrap(),
                key
            );
        }
    }

    /// Checks redaction in both private key debug formats.
    #[test]
    fn diagnostics_redact_private_material_in_both_debug_formats() {
        let key = MlKem1024DecapsulationKey::from_seed(&decode_hex(SEED));

        assert_eq!(format!("{key:?}"), "MlKem1024DecapsulationKey([REDACTED])");
        assert_eq!(format!("{key:#?}"), "MlKem1024DecapsulationKey([REDACTED])");
    }

    /// Deterministic entropy source with injectable partial failure.
    #[derive(Debug)]
    struct FixtureRng {
        /// Offset of the next byte in the deterministic entropy fixture.
        position: usize,

        /// Optional byte count at which the source reports failure.
        fail_after: Option<usize>,
    }

    // Deterministic and deliberately insecure.
    // This implementation is test-only.
    impl TryCryptoRng for FixtureRng {}

    /// Synthetic error from the fixture entropy source.
    #[derive(Debug)]
    struct EntropyFailure;

    impl fmt::Display for EntropyFailure {
        /// Formats the synthetic entropy failure for error propagation tests.
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fixture entropy exhausted")
        }
    }

    impl std::error::Error for EntropyFailure {}

    impl TryRng for FixtureRng {
        /// Error returned by the fixture entropy source.
        type Error = EntropyFailure;

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
            let seed = decode_hex::<64>(SEED);
            for byte in output {
                if self.position == self.fail_after.unwrap_or(seed.len()) {
                    return Err(EntropyFailure);
                }
                *byte = seed[self.position];
                self.position += 1;
            }
            Ok(())
        }
    }
}
