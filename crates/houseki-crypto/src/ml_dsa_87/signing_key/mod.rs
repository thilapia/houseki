//! Protected ML-DSA-87 key ownership with explicit seed generation and import.

mod error;

pub use error::MlDsa87SigningKeyError;

use super::MlDsa87VerificationKey;
use crate::random::secret_bytes;
use getrandom::{SysRng, rand_core::TryCryptoRng};
use ml_dsa::{Keypair, MlDsa87, SigningKey};
use std::fmt;
use zeroize::Zeroizing;

/// A private ML-DSA-87 signing key with protected backend ownership and fixed diagnostics.
///
/// Generation obtains a complete guarded seed, while exact borrowed import cannot establish
/// entropy or provenance and leaves original seed cleanup under the caller's control.
///
/// Stored backend seed and expanded key fields are zeroized on drop with the pinned feature.
///
/// This does not clear every backend temporary or compiler and operating system copy.
///
/// No private export, cloning, equality, hashing or serialization interface is provided.
pub struct MlDsa87SigningKey(
    /// Owned backend secret with enabled stored material cleanup on drop.
    pub(super) SigningKey<MlDsa87>,
);

impl MlDsa87SigningKey {
    /// Number of bytes in the independent private seed representation.
    pub const SEED_LENGTH: usize = 32;

    /// Generates a fresh key from the system's fallible cryptographic entropy source.
    ///
    /// # Errors
    ///
    /// Returns no key if any requested seed byte cannot be obtained.
    pub fn generate() -> Result<Self, MlDsa87SigningKeyError> {
        Self::generate_with_rng(&mut SysRng)
    }

    /// Imports an exact borrowed seed, accepting every byte pattern without an entropy claim.
    ///
    /// Keep this seed independent from encryption, spending and nullifier material.
    ///
    /// The original import buffer remains the caller's responsibility to clear.
    pub fn from_seed(seed: &[u8; Self::SEED_LENGTH]) -> Self {
        let seed = Zeroizing::new(ml_dsa::Seed::from(*seed));

        Self(SigningKey::from_seed(&seed))
    }

    /// Returns an owned operational copy of the matching public verification key.
    pub fn verification_key(&self) -> MlDsa87VerificationKey {
        MlDsa87VerificationKey(self.0.verifying_key())
    }

    /// Acquires all seed bytes under guarded ownership before constructing a key.
    fn generate_with_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<Self, MlDsa87SigningKeyError> {
        let seed = secret_bytes::<32, _>(rng)
            .map_err(|_| MlDsa87SigningKeyError::RandomnessUnavailable)?;

        Ok(Self::from_seed(&seed))
    }
}

impl fmt::Debug for MlDsa87SigningKey {
    /// Writes a fixed label without inspecting or formatting backend secrets.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MlDsa87SigningKey([REDACTED])")
    }
}

/// Standard key generation, complete entropy acquisition and fixed redaction.
#[cfg(test)]
mod tests {
    use crate::{MlDsa87SigningKey, MlDsa87SigningKeyError};
    use getrandom::rand_core::{TryCryptoRng, TryRng};

    /// Parses public standard fixture hexadecimal without production codec dependencies.
    fn decode<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);

        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }

    /// Checks NIST ACVP ML-DSA-keyGen-FIPS204 tgId 3 tcId 51 against the complete public key.
    #[test]
    fn ml_dsa_key_generation_matches_nist() {
        // NIST revision 2972def23bf9f3680c2c531561ed9bdd0f1086ad.
        // https://github.com/usnistgov/ACVP-Server/tree/2972def23bf9f3680c2c531561ed9bdd0f1086ad/gen-val/json-files/ML-DSA-keyGen-FIPS204
        let seed = decode::<32>("A16F5B0796703E2D1A0140A35CBF36EFABE70E752BA59B6A9A0E9C4B05302F73");
        let expected = decode::<2592>(concat!(
            "A5787E8044248F3F85AAC54E9469FC98F1B1138CC127B120F9946C80B96E3D89CCFE38C995645D4B6A559EACB2AFB81621D765C6E42E73031D44CBE74D322C7B",
            "16249576EB4C500253538D1A2C6B408E681B93B9014E3147DFBECF9D9858F7E8635F8598BA6847127D216A888FFB1636CC761616A0389C39A4245695DDE0C86C",
            "CF8A3BC5A50EA6FDBCC0A34457D4DEFE35F775C5993685AEF2237C31912A619FF804AFE8AC3418C13502820AEE5249D6E577EE0B2A5E3E8DA2DD30F514A076B5",
            "0556D7581BA1F9B2E4671756A63065C20EBDA6EE2C33C9D97AB14C5F2204FC5359ADB2BDAA3AAB7AE1DACFF18A67D801BCB8F054BBC444F0FD0001A7908EBDCD",
            "F2B84F3C026EEC1282498D31AC33AE6A309ACAB17B70DC9F0EFBE52648D1AD2A4CD5964DC619B66CDC9D35EDA7A3DC21C729B9929024DB8B852DFDF102A08684",
            "5702FD249EE43B54D2D033ABA95110C4F0A66EEAEE78F3C41D5D792A37D1D2299252A5498A44CA354F6F37FDC2F3B72B1A8378A5BA8B4997556E5A6F4125AD94",
            "6BD4FC402C4320B27111BC204B8B5448F43F7E77A8166A48137D85584BEFE2D9C85CCCD9BBF3F8A4E05930180AFDD697DA82ED9F1069150FFC76578C941CDBCC",
            "5BD2ECB7D6ABF9E68327DF51C26C8B42CB1DD8BDA98A82C4C6BA6A991E651BDFF68F0A62D5DBFEA020D4303E0C53D474CB11D553C5BEE1156917D72AC2A6CCC4",
            "EC1C775D41EE660E2485A45AF5A7CA083DDDCC3EE4FFFC5E77BA97CC4473303C77D8B6FDB35E2A20627BEBBE327DD2D1AD1F880CA8EAE1E0067A9093929E5AB1",
            "8D406A518EDD8C1E0F0AB07736F55FCECF4A3B2ADCE1CE3E080B58DDF85A2262D0803A7E5B4E485E642BA533E2EC7A43F9E8DB20F75292ADAC704395469408C1",
            "5641A9C28B83E8C1C799FAE0652F51369978F4C089FE15DD78C5F560CD28F5F75FE0A39A60A61AEF6C7D802141E9809E7ACA68A38BE9BDF5312258704F8B11AF",
            "4262220CB55641FE95DF83EC9F786D6E69202C91EC4CAA4E38A21C3CC609C28B8F65552FE8334850858BBB30B837D874867EAD330A1F5B4D7F6BEC4748BE54A7",
            "82D5B21A192BC00A7F2240FBD900460785D1971A94C587493D21CDA249676EDAC6C865147E269488B9CA78FAEFDC778FF60E79735DD5539879182424B054FAE8",
            "A9E153BFFD6957C533AEDC105E43AD7626312C8D229327D3E72AA9644BF3E2C9A08ABF807CF3A472C7DAF0AC4290A9E8F88D07AE8FEDB8A4B218C3EBBDBE5388",
            "2781F2DE034B17FEFE69302B4975CF43E03645DC53BD355AF988B3A3D2431BF9D9A865750051EED7BAEFD1BAD4939C7EC293509A5851A145F79DCBEEFD195571",
            "AC2172AC6036812B4DC8040D186B8984CF9DC24F8F765166C6B2E8389DD24ED63CEE951442861669BDA0622BD90B041DC477C01A0D95D547E07A892CE1F26275",
            "ABC6F97702E03B776E2CA71E3D0EBB88D1ADF591122E6F0EC95A6CFBB976AE64BD0C7F074CB6E78E644DEE8200E2D626435907B9134000DBC3B50271F5A8F254",
            "D2CF02DA039D458E80FA13A33567AA9B374B47B799D0FF1A14CA92A50EFA192EA1641FE29A380E11386528B7248D6DE6AA90E1C9744713B768264B72A13CCAA9",
            "4F3E19ADA5129E0D8155EC1B267E2CDC7F0E7A08F203D9A18F8C8D18529709EF746A21D5FEC36EB547A2FD4490092AD0F06C55EE0A1CB104E2C3C3CF2BCBCBFF",
            "EAEC744A13E37310962CE40E072E7ECAE223943A03002077D3D96C7B4C3FB1E2C9EE9C5222A63252F26372BC2BD94507CE5728CEB7A0AA33527E0662B4561D1B",
            "D255806450772EABB7ED40F787A2E3C664FA6BC3BE9BCD84FC7B42F16F94CC56CFB67297E475177E19E51010CFB74BA996BA1C3D793EA010C99901E2223B375E",
            "364BA193772B329D5D05AED959EBB924B698F0657AF43EEE8E0D54D15C93511209AAA9E10251BF81AD8B467D8FAEE2A440782C372F55A62CFEF408803E4B3BD8",
            "EFB94061EAB525BD31957779B89EB1C75AB97F278B3EAF99A05686E04873D7A685868D1C0F4510ADAB0B267FE4D3CB70C35B295AFC671B60C6575B60EEB99756",
            "E7B204A24D7095DF277BE18668E0F1AA5621D16F204575F76C3B13385BAF61AFF7F36D56111FD88FF093BEC4FFC26BA63720660B5BD209A9C14C0AC6B4E08B38",
            "FF580C18E39A22A9AC36912892537B0FD42800445DBEF1A03D2D8624C1B125519927C282EEFAC4AFC16128B07456FBC99D34C783AE08EBB0C46915971429FE64",
            "E448F1678BF76C7C20F91AD80E213E39AD89962AEA44E06EAB351C9B3A5859D5A884DE0CD767260CB60A96F508C62B731047CB1F3CA6AE28742771F4EC3BE45D",
            "F500F0132B6E947D2468AAB9410BC1F581328471B3E53E8E29A0794F4EA8BDF9FDB3922CECBD2AAAF75A2AF4C7CEBA03382332D39DFB770559789708930E4C77",
            "966C7364E2A4D762C122BE3FCBD37276EA6194071BB7C18E2627524F3AB2BE7C0C6E59F62D1F075E1951DD3352F6CA9762F243F6691FE6A9DCE4278B178F688E",
            "433B990272000F23C92F74A1CFF1429BDF1C3FE1B9AA1C0E7A58ABFFBB54D3F38ED93B11FB12233CFF48C812A227747849012F7BB85529D87459E11DCA9F7A9C",
            "3242054DB6BB93B48A47D69BA791B2A5D694A8776B22B8881BB2D192AB0A45AEC71A7171F844E3B1C4149D118EFA899E88D96A296D5EB811AF923AFD1A92E0C7",
            "1464B90C8E5EC24954FE8C9BFB518A308B3D301D8D6C62E5AD40F63BCE24699AF0BBD2E48FD9AA7C3A1C597731700E3D86E16AD36A67BC031BF381B82CF40B1B",
            "235F51727913BBC311A186FDC23EE267739740CC57C36BE05F9331EA40279C34C44FB8FDFCC7E9CDA54C394CEF9C17F8529A56E3BCCBA327CABD07F5F9C567B7",
            "0DFBD9D7139E39B7E1A493482321B11C881BA9D44CBABEA64F1AF18C18B3B5F98FF4A95FD907E112AED857B033BB7E0FF9466CF5FC691CCC1142BFB8CE81BAD7",
            "DB554409B79E23D0A41063857E4AA05583525E69EDAA017F6A7FA96C25A38E7A7D01E22F96ADBB683B4EB8A487202426D68D297B30BE0A803D4FCA1E037DB3BD",
            "63A2F06EFD68BD4D7BEAD8338D36AC1425163B3C739B86AC9D967ED54DE24CA58BC129CFF73585B667DC33F32BC4A4D9E106076849BC2574F0E5AB2C0B5CBDBC",
            "A59BB644BC86F3339B23B3B12959FC7887F7291136343E54F4A56C344DC5BE641DBCE62AED4D4BB958C4D54D7196DB4ACB8A1F43F88CDBB758546F44C5929350",
            "1E0569F00B97FC244507C248031D07EE4DBB6A97270B772791E758E582989D93124AB82F15A9DCA469C1A0E98CC75FF683430036F16B4E94E94DECA06EBE7FE2",
            "B8E9C0A690AAD7A91877799FCF24CE275844A63E68F1A5C799BC83C7F5384CD9322E20B619D39D0031482FFED8224F6C522C8533CB29C04AF154D920D747D816",
            "16EA219E358385AA9FDB8E94A7EE5B53F2CC31B3A7BAC787E54AB9536FC42A3E369043C6F5C11D0F7D452852C3FB3F1845942186044385FB9E482962B1DAEBD2",
            "B3DF125D1A61843F71A272E3A1D97AAB97DE5831C56D16A6A6620F8C6CD0F4F1E41AFE6895BA3664D23A03EAB3531126E87335F4BCBBF2E39C47B5A58BA15066",
            "F79717D8296667553ECD0991F14D42F8934D753929F146E4B58D00A3E0139D66"
        ));

        let key = MlDsa87SigningKey::from_seed(&seed);

        assert_eq!(key.verification_key().to_encoded().as_bytes(), &expected);
        assert_eq!(key.verification_key().to_encoded().as_bytes(), &expected);
    }

    /// Rejects every partial acquisition and a full write followed by a reported failure.
    #[test]
    fn generation_requires_complete_successful_entropy() {
        for failure in 0..=32 {
            let mut rng = FixtureRng {
                failure: Some(failure),
                position: 0,
            };

            assert!(matches!(
                MlDsa87SigningKey::generate_with_rng(&mut rng),
                Err(MlDsa87SigningKeyError::RandomnessUnavailable)
            ));
            assert_eq!(rng.position, failure);
        }

        let mut rng = FixtureRng {
            failure: None,
            position: 0,
        };

        let key = MlDsa87SigningKey::generate_with_rng(&mut rng).unwrap();

        assert_eq!(rng.position, 32);

        let expected =
            MlDsa87SigningKey::from_seed(&std::array::from_fn(|i| u8::try_from(i).unwrap()));

        assert_eq!(key.verification_key(), expected.verification_key());
    }

    /// Keeps diagnostics independent of secret bytes and obtains distinct fresh system keys.
    #[test]
    fn signing_key_diagnostics_and_system_generation() {
        for seed in [[0; 32], [0xff; 32]] {
            let key = MlDsa87SigningKey::from_seed(&seed);

            assert_eq!(format!("{key:?}"), "MlDsa87SigningKey([REDACTED])");
            assert_eq!(format!("{key:#?}"), "MlDsa87SigningKey([REDACTED])");
        }

        let first = MlDsa87SigningKey::generate().unwrap();
        let second = MlDsa87SigningKey::generate().unwrap();

        assert_ne!(first.verification_key(), second.verification_key());
    }

    /// Predictable seed acquisition with a complete or partial reported failure.
    struct FixtureRng {
        /// Byte position at which acquisition reports failure.
        failure: Option<usize>,

        /// Number of fixture bytes already written.
        position: usize,
    }

    impl TryCryptoRng for FixtureRng {}
    impl TryRng for FixtureRng {
        /// Fixed test source failure without secret diagnostics.
        type Error = std::io::Error;

        /// Supplies four fixture bytes through the common checked fill.
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;

            Ok(u32::from_le_bytes(bytes))
        }

        /// Supplies eight fixture bytes through the common checked fill.
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;

            Ok(u64::from_le_bytes(bytes))
        }

        /// Writes through the configured position and reports a possible final failure.
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for byte in output {
                if self.failure == Some(self.position) {
                    return Err(std::io::Error::other("fixture failure"));
                }

                *byte = u8::try_from(self.position).unwrap();
                self.position += 1;
            }

            if self.failure == Some(self.position) {
                return Err(std::io::Error::other("fixture failure"));
            }

            Ok(())
        }
    }
}
