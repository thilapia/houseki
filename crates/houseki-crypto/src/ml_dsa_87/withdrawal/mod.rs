//! Direct randomized signatures over complete canonical withdrawal bodies.

mod error;

pub use error::WithdrawalSignatureError;

use getrandom::{SysRng, rand_core::TryCryptoRng};
use houseki_types::{
    BodyCodecError, BodyCodecLimits, EncodedMlDsa87Signature, RewardWithdrawalBody,
};

use super::{MlDsa87SigningKey, MlDsa87VerificationKey};

/// Fixed FIPS 204 external direct signature context, independent of other signing roles.
const CONTEXT: &[u8] = b"houseki/v1/reward-withdrawal";

impl MlDsa87SigningKey {
    /// Signs the complete actual withdrawal body with fresh system signing randomness.
    ///
    /// The fixed direct ML-DSA-87 context and framed message bind kind 2 and the complete
    /// canonical V1 body, including every encrypted envelope byte and excluding proofs.
    ///
    /// Stored key cleanup follows [`MlDsa87SigningKey`], without clearing every backend temporary.
    ///
    /// A signature establishes neither account registration nor nonce, balance or proof validity.
    ///
    /// # Errors
    ///
    /// Checks the body's authority before canonical byte limits and framing, then obtains entropy.
    ///
    /// No partial signature is returned on an encoding, framing or randomness failure.
    pub fn sign_reward_withdrawal(
        &self,
        body: &RewardWithdrawalBody,
        limits: BodyCodecLimits,
    ) -> Result<EncodedMlDsa87Signature, WithdrawalSignatureError> {
        self.sign_with_rng(body, limits, &mut SysRng)
    }

    /// Signs with an internal fallible source after fixed authority and message preparation.
    fn sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        body: &RewardWithdrawalBody,
        limits: BodyCodecLimits,
        rng: &mut R,
    ) -> Result<EncodedMlDsa87Signature, WithdrawalSignatureError> {
        match_authority(&self.verification_key(), body)?;

        let message = message(body, limits)?;

        let signature = self
            .0
            .expanded_key()
            .sign_randomized(&message, CONTEXT, rng)
            .map_err(|_| WithdrawalSignatureError::RandomnessUnavailable)?;

        Ok(EncodedMlDsa87Signature::from_bytes(
            signature.encode().into(),
        ))
    }
}

impl MlDsa87VerificationKey {
    /// Verifies one direct contextual signature against the complete actual withdrawal body.
    ///
    /// The supplied key must equal the body's declared authority, with actual account binding,
    /// registration, nonce, balance, fee policy and output proof checked by their consumers.
    ///
    /// # Errors
    ///
    /// Checks declared key equality, active canonical limits and framing before signature parsing.
    ///
    /// Invalid encodings and failed signature relationships share a fixed error without a success value.
    pub fn verify_reward_withdrawal(
        &self,
        body: &RewardWithdrawalBody,
        signature: &EncodedMlDsa87Signature,
        limits: BodyCodecLimits,
    ) -> Result<(), WithdrawalSignatureError> {
        match_authority(self, body)?;

        let message = message(body, limits)?;

        let signature =
            ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(signature.as_bytes().as_slice())
                .map_err(|_| WithdrawalSignatureError::InvalidSignature)?;

        if !self.0.verify_with_context(&message, CONTEXT, &signature) {
            return Err(WithdrawalSignatureError::InvalidSignature);
        }

        Ok(())
    }
}

/// Requires the operational public key to equal the full declared body authority.
fn match_authority(
    key: &MlDsa87VerificationKey,
    body: &RewardWithdrawalBody,
) -> Result<(), WithdrawalSignatureError> {
    if &key.to_encoded() != body.withdrawal_public_key() {
        return Err(WithdrawalSignatureError::AuthorityMismatch);
    }

    Ok(())
}

/// Frames the fixed kind and actual canonical body after bounded encoding and checked reservation.
fn message(
    body: &RewardWithdrawalBody,
    limits: BodyCodecLimits,
) -> Result<Vec<u8>, WithdrawalSignatureError> {
    let encoded = body.to_bytes(limits)?;

    let domain = crate::domain::Domain::WithdrawalSignatureBody;
    let overhead = 2 + domain.label().len() + 4 + 8 + 4 + 8;
    let length = encoded
        .len()
        .checked_add(overhead)
        .ok_or(BodyCodecError::LengthOverflow)?;

    let mut message = Vec::new();
    message
        .try_reserve_exact(length)
        .map_err(|_| BodyCodecError::AllocationFailed)?;

    let mut sink = |bytes: &[u8]| message.extend_from_slice(bytes);
    let mut frame = crate::domain::Frame::new(domain, 2, &mut sink);
    frame.part(&2_u32.to_le_bytes())?;
    frame.part(&encoded)?;
    frame.finish()?;

    Ok(message)
}

/// Complete body authorization, standard conformance and fallible entropy boundaries.
#[cfg(test)]
mod tests {
    use super::CONTEXT;
    use crate::{MlDsa87SigningKey, WithdrawalSignatureError, withdrawal_transaction_id};
    use getrandom::rand_core::{TryCryptoRng, TryRng};
    use houseki_types::*;

    /// Admits the independent three byte opaque envelope fixture without claiming its recovery.
    fn limits() -> BodyCodecLimits {
        BodyCodecLimits::new(PaymentCountLimits::new(2, 2).unwrap(), 3, 5000)
    }

    /// Assembles exact public fields under a real matching immutable account authority.
    fn body(key: &MlDsa87SigningKey) -> RewardWithdrawalBody {
        let mut bytes = vec![0; 4439];
        bytes[0] = 1;
        bytes[4] = 2;
        bytes[8..72].fill(7);
        bytes[72] = 2;
        bytes[76] = 3;
        bytes[80] = 4;
        bytes[84] = 5;
        bytes[92] = 8;

        let public = key.verification_key();
        bytes[100..164].copy_from_slice(
            public
                .reward_account_id(NetworkId::from_bytes([7; 64]))
                .unwrap()
                .as_bytes(),
        );
        bytes[164..2756].copy_from_slice(public.to_encoded().as_bytes());

        bytes[2756..2764].fill(255);
        bytes[2764] = 3;
        bytes[2780] = 17;

        bytes[2796..2860].fill(11);
        bytes[2860..4428].fill(12);
        bytes[4428] = 3;
        bytes[4436..].copy_from_slice(&[0, 1, 2]);

        RewardWithdrawalBody::from_bytes(&bytes, limits()).unwrap()
    }

    /// Preserves body identity across fresh signatures and distinguishes every complete public field.
    #[test]
    fn direct_withdrawal_signatures_bind_the_complete_body_and_fixed_context() {
        let key = MlDsa87SigningKey::from_seed(&[0x59; 32]);
        let public = key.verification_key();
        let body = body(&key);

        let first = key.sign_reward_withdrawal(&body, limits()).unwrap();
        let second = key.sign_reward_withdrawal(&body, limits()).unwrap();

        assert_ne!(first, second);
        public
            .verify_reward_withdrawal(&body, &first, limits())
            .unwrap();
        public
            .verify_reward_withdrawal(&body, &second, limits())
            .unwrap();

        let id = withdrawal_transaction_id(&body, limits()).unwrap();
        let parsed =
            ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(first.as_bytes().as_slice()).unwrap();

        assert!(
            !public
                .0
                .verify_with_context(id.as_bytes(), CONTEXT, &parsed)
        );

        let message = super::message(&body, limits()).unwrap();

        assert!(!public.0.verify_with_context(&message, b"", &parsed));

        let domain = b"houseki/v1/reward-withdrawal/body";

        assert_eq!(&message[2..2 + domain.len()], domain);

        let original = body.to_bytes(limits()).unwrap();

        assert_eq!(&message[message.len() - original.len()..], &original);

        for offset in [
            8, 71, 72, 76, 80, 84, 92, 100, 163, 2756, 2763, 2764, 2772, 2780, 2796, 2859, 2860,
            4427, 4436, 4438,
        ] {
            let mut bytes = original.clone();
            bytes[offset] ^= 1;

            let changed = RewardWithdrawalBody::from_bytes(&bytes, limits()).unwrap();

            assert!(
                matches!(
                    public.verify_reward_withdrawal(&changed, &first, limits()),
                    Err(WithdrawalSignatureError::InvalidSignature)
                ),
                "offset {offset}"
            );
        }

        assert_eq!(withdrawal_transaction_id(&body, limits()).unwrap(), id);
    }

    /// Rejects authority and active byte bounds before any signing entropy request.
    #[test]
    fn withdrawal_signing_checks_authority_and_limits_before_randomness() {
        let key = MlDsa87SigningKey::from_seed(&[0x59; 32]);
        let body = body(&key);
        let other = MlDsa87SigningKey::from_seed(&[0x58; 32]);
        let mut rng = FixtureRng {
            failure: Some(0),
            position: 0,
            bytes: [0xa5; 32],
        };

        assert!(matches!(
            other.sign_with_rng(&body, limits(), &mut rng),
            Err(WithdrawalSignatureError::AuthorityMismatch)
        ));
        assert_eq!(rng.position, 0);

        let tight = BodyCodecLimits::new(limits().payment_counts(), 2, 5000);

        assert!(matches!(
            key.sign_with_rng(&body, tight, &mut rng),
            Err(WithdrawalSignatureError::Encoding(_))
        ));
        assert_eq!(rng.position, 0);

        let signature = key.sign_reward_withdrawal(&body, limits()).unwrap();

        assert!(matches!(
            other
                .verification_key()
                .verify_reward_withdrawal(&body, &signature, limits()),
            Err(WithdrawalSignatureError::AuthorityMismatch)
        ));
    }

    /// Requires successful acquisition of all fresh signing bytes, including final reported failure.
    #[test]
    fn withdrawal_signing_rejects_partial_and_final_entropy_failures() {
        let key = MlDsa87SigningKey::from_seed(&[0x59; 32]);
        let body = body(&key);

        for failure in 0..=32 {
            let mut rng = FixtureRng {
                failure: Some(failure),
                position: 0,
                bytes: [0xa5; 32],
            };

            assert!(matches!(
                key.sign_with_rng(&body, limits(), &mut rng),
                Err(WithdrawalSignatureError::RandomnessUnavailable)
            ));
            assert_eq!(rng.position, failure);
        }

        let mut rng = FixtureRng {
            failure: None,
            position: 0,
            bytes: [0xa5; 32],
        };
        let signature = key.sign_with_rng(&body, limits(), &mut rng).unwrap();

        assert_eq!(rng.position, 32);
        key.verification_key()
            .verify_reward_withdrawal(&body, &signature, limits())
            .unwrap();
    }

    /// Groups invalid signature bytes and rejects repeated hint indices under the fixed direct mode.
    #[test]
    fn withdrawal_verification_rejects_noncanonical_hints_and_altered_signatures() {
        let key = MlDsa87SigningKey::from_seed(&[0x59; 32]);
        let body = body(&key);
        let public = key.verification_key();
        let signature = key.sign_reward_withdrawal(&body, limits()).unwrap();

        for index in [0, 63, 64, 4543, 4626] {
            let mut bytes = *signature.as_bytes();
            bytes[index] ^= 1;

            assert!(matches!(
                public.verify_reward_withdrawal(
                    &body,
                    &EncodedMlDsa87Signature::from_bytes(bytes),
                    limits()
                ),
                Err(WithdrawalSignatureError::InvalidSignature)
            ));
        }

        let mut bytes = *signature.as_bytes();
        bytes[4544..].fill(0);
        bytes[4544] = 1;
        bytes[4545] = 1;
        bytes[4619..].fill(2);

        assert!(matches!(
            public.verify_reward_withdrawal(
                &body,
                &EncodedMlDsa87Signature::from_bytes(bytes),
                limits()
            ),
            Err(WithdrawalSignatureError::InvalidSignature)
        ));
    }

    /// Parses complete public NIST fixture bytes for backend conformance only.
    fn decode<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);

        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }

    /// Checks NIST external pure randomized ML-DSA-87 tgId 33 tcId 481 against all signature bytes.
    #[test]
    fn randomized_direct_signing_matches_nist_external_fixture() {
        // https://github.com/usnistgov/ACVP-Server/tree/2972def23bf9f3680c2c531561ed9bdd0f1086ad/gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1
        let seed = decode::<32>("98E5CAECEA6F6F6FFD17A364592BD5AACE8D9F1725D521DCB18E76B1E8E263EB");
        let random =
            decode::<32>("0787D97128B120777FC1BABFFB965EFB3221FA95ACB1284B12B93211BB358E37");
        let message = decode::<2779>(concat!(
            "9B10A3BC87771442151295D4F6218D0D272CE0E9BCAFA6A10A4F49EFD71A2EC9ED2394011F3B5A9DFC58FDFAEF15D2C27FC709CB66365D3012C3F8E115119A12",
            "0C85E9C9E30DD430F8461F19DFB86502305E01712D3B4FD6ED770EF46B52E41C71DCB35517032080383606B50D4BA720B86433F92E0CEFBFDB01CD038E0C66FE",
            "FC2C6587D91D6663572F7D1CFA2AD8BA7B9C01D250E048D6648C737E6777B0B65300DFE50622BDB93683D977E3534C4E80347B3EC3BAFFDB116BAA97D79DE731",
            "A66070467858EFF6DBC48C4FBC5A420E234B1C4EA95716C347583DF519997EC3D396D125616F999C822595D97D46334F60C3305661BAC77885D2B611F5711B70",
            "9E0A96F0A9A2D154A17E0971CF9C96FE69326734091CCD6A867BC733C43A1B8B96657613459D82C7F83A722F244EF44D067A4C10FDB2D5141EDB8E2C6ACA8E13",
            "AD2EC0C3EA9C78B64364E7DF31EC4614A731FE524EC8B9562860B0BD54C52CDF1AA31B6B639B7F04CD9AD8B708FE75CE99E2F196A9A8B7C899235F69A046501C",
            "1CEFDEA6BAE0F699C8A7FB0591537988CA5104A5E149CFF849D64B5A3548ACC8A06A0A82873F1F9E87D2E078A1019FE47D94B24D0EF186277266E5DA7E7E6CA9",
            "209C073037F71D7C9E12966770415F2FB0C9D8A1F1CD65A79A427AA5BBBDB01D3A51BA00304FAD5536A31A74982169EC0BA1982E9BA6FADB9D3780E44C5320B8",
            "872F89DA2E6AD048F87447EBA802DF1B26C7F9DC76374DC32BE96B0098A5C97E8FC376783C90B3047D0E66E96A25C50838188A16D1B07CFEA7C56AE26F4D575F",
            "5DB2116E0B1733B1DDCA8CF235F48896CCDA4EEF042730A131828F6F4191CF0A019CDEF3BB91E386078F3E0151AD803634AC743E5858FC3BA5CD00EF9E3B401C",
            "CCDEA0B62BBD424019A6480062D56F32722DAA82AD9CE8A25309B1FED2FD2D5090A0D7C1DFF364DF2F22DB40FA4F4556CCD3EDCB8BD1BCA39F80A98F9D7263F4",
            "E74350A82B3B055FF836536A408822FD994E7136F21493E04902FCE4525C16838D1BC91D4DDEA53D09DFE01FB206A69C65FCECB4F5F010B0609E86D0780E3FD9",
            "550670E62487FA8503662702C5F47FCFD375F392356C89FE01EEA54764A8A430E2A61331D57911588F22207FEF129F05E6EB791D3E227F6937466036E089A824",
            "E6161565FA65BB4C9232B5B4D6C144622585D10DCC8A46F80B0D9690C6A48A44D7F7403474C48BB7F845A7851A8A77CDD726DB6BCE7F1B264A892A851CB3923A",
            "B7CF3F4D8E1C8800F1A08CE7B190823593B34458DE42141644CF50FDC57C57852D58169CBF0B811C7EB9ADE2965FF59A87EF027438BF93CD6CFF590F3807BA9E",
            "822347A72B092496287D17710F81169EDF89047F1BDAA874FF42A6E4A1A999962BBD63ACFED5248C6F1D4FE134930F13E4FAB9D29EE65BE6D0457C509593B377",
            "5F4C051F94FA98985BA26676C079BA7C923B785520F8E230DCF8A7966D7F2ED594105BEE0FA24F5C4FDACA801738DE77DCEACFC4694787BA3B14C1E356E87226",
            "237DAE9FF197666200E19CA8B21D459EDBFE7FE0A5525242AF4C8675044F3EEC827D9E5CD7B9755CCA7516BC8A3706C18AC63295D5F5A4C1DA865966F330D717",
            "9D27E0B9DECF650E9355D64A142DC908B379A6DC66DC1463377D2C3CC709B1A0BF2BE95340B93A30A29971EA58DB3F07C22070A5D19742877B2073190007A704",
            "3F2F2553348B29231F7873A9638F83AB962D436E0DF1CFE57E1EDF69DD59A81642D57ADC86D634068F7D97A17CC1A65A895073A91DE9DABA0BAC296992B9A1B6",
            "19F06A0AEA0DFC0AD66158E8ABDB91A88771227E10C207ADDF65E982E00A68E865437C0E6A2DCCACCF846B2496B91FF52F0A73FAA107F996FFD437B7B9CB8E41",
            "86EFA1CBD0C0B2FB6CC48509580681171CA34E6F4CEFD7070E4DCF1C293870548DC32B18D03C987D79C0E9790E07E3CEF160F02A201C05B2077207693E2BBC56",
            "3D94113BD472780DCD6F8B51A1DF7915B70D48E58FADE99FFFFF8B484966EC04128B58881D9ADB39467FD709BC04B193BB51D02A30CEE1951C2FD6AFACBE8DA5",
            "78475653723566873778B3704305CED5AF3707D70B654C68DECBBD842113B1F9F01B0F8ADA61CBC228DB8F7C36C061DAB3F8C25EB87EC088D230B43DF78F62C7",
            "F4EA30A5E081CE7296BF55CCED1E989209B51384DAA6E421C0EF0CA8D361827DA77D9ACF526A90C67D9D049C9F8078DED8879E7A0C0A458FB9831070484B0F9A",
            "5CF44C65FD7019A82F208F20359DA4D06054F3E2FBDE72F4E397406C13BFE60CBE3A3A4451D833CB6A9A587FFF2827F9F023302F58CDD597399E3E313C844388",
            "9F8E495D9795F391844BB0D076AB9221C87CF15648869B0797D2D94569B8171B6BCF2A924AF076E17979B5F4D46C6912E3A8E9539FAE57CA21934D0D766D0A3A",
            "3F853DDFBD75CAB2D09005A050BC9AE4E050B274F257A0A9AEE80715A246717E1906B16F514A62951DDBAA405706B229A9EF54E8EC2440F0F58F29200BE78D7B",
            "D05CA603E644D434389F9832489638D80913FC2FC142DBC00997B4267F9A35B50DF3D78FDFBB3CA61F162AC8E44988A9B5A8BB419D9B6EA7EC86BE22EAF44B63",
            "677D7CD040ED81C4549ACB30EAC846C8B99E1ACAFE9C328AC3177D61809140EA4615902B114148CF73B9DED02531BF69E73EB42ADE9278F7A88E1188BDF57E32",
            "6AF161A9312E066DC9F95C7694DB19D5A03A56FEC4AADBA8BEC25918AF11C8CF3072AB3E065FA43D3D78D5BA3A37B902A7C19A85C5AEA515306809D56B44E69E",
            "B397AD4EDEC0963AC01BAC69C00B10C897C55D96AF7C67DDC189FF9D9A6458EAE295C64BFF51C804574A012C8C679F2F05A33AC42EC83479E2ADA0A6C5EE85C1",
            "4738D1603B166CD28A8B5EE3F54A8B6230C48B1F26A023B3F501626C235290B62EF77617C9D0F491C36065517B297B4519C4F955A4B3B9BD509B302FA72F32EF",
            "DCDA0D718FA5272A1A30D2DF5E734E2631099C56426D903C6805BCF0FA0EC1963FC3C4CA4FAC4EB61A3CC234EF22C20D8B2A3D68C672B3A1A45D1DDD5B4266DC",
            "65C2022080DA516E7262C8F60E359986E2183261EA265841E445A4A11BC118E332D16A89A9A525BE8B288F1EB497E649FE399F742599ADCF4BABC6A599DD9701",
            "817C8DF57E98BF828C58FA98F5A3EDAAEB3E7EB2C39A5FC0C7E9216828B21786C184C2A142D2877CEC620E855974B86C13EE57B0635886431DD0C70615ABE59B",
            "DD530DAD10019943EEE10B4ADD7D908FEF36140D4DF4DACE32D2A2DC15765EF7ADEB02E904A8A328FBA5A53D27B915C0ACDD7D73A39287E03D1156B32995E894",
            "1E3303F33D3C6C6DAAB79FD4D517E08986CB71FD0B7D2AB1DF402670154DE09A797A5508429C8B1DDB89F0CE43662064826C010930610F733B468FC95A47F69A",
            "86E23AF67B62F587D5A25F1BF066F76F0980B80CE8667DB371D16B372460BF3AA4E1343AD52AE43A78EA6FAD158044A67EB32A1A819B7CBA1C1020609D6D7245",
            "4F749B350C7623349A39A765219AC4913108A596A60FAE401741B1F85E7F74204F9047D91276AE244AD02930DB94FBCD097FE0118EC2D6974EAEACBB9A6D04C4",
            "6A82F91C68CD11121934587CA7FDEEC4FC4B666344DEA349ADAFA72488C858A34CD02DC958F81970E224F0310B8447F5D23584F2105195984C5115813DF3360A",
            "656400EEF3C0F9803E77B4D977EF9AC331E517BFD3BD074DBF218A517957E796FD6721A64778DBEAF557B0189E54B9D6A38ED9258A3472860A4767CEABEED8EE",
            "90522D30C63E520A0AA2F44544119526EF3540514677E92B98E7E49983E58CE99CF52A337AA80CE3E01F9D74600B6EEEE1EAB337D774E4BA86A8D9D222322AA7",
            "165450B3007710A36D18C62A3270D472BA06CCAD8DA33DECA82BAB"
        ));
        let context = decode::<192>(concat!(
            "A00FC197D635EFD3AC18FEDDE792C2A2DF922E716781B6C81EB0A61884CC8F7D9EA151BE393D8D60926116627946FCB9D1B7DE4AB32CD9F2CDFAD564968234C2",
            "7B7723E44B9459BDDCE19D407384C2F3153D9AB98F0AF5C2859D5393FB6A422FA189E73B3A12F66C706D55A8EF5E90208DD1CFD9B2D64C62B35EF64200CA2B32",
            "8A8C9E03A550C5E4164C90DB6CA8217BE0535D279CCCBC408D8C8BFFF60DB80049C25110DA7074EAF86CA56E17D9EE3F5EEC4FB9CB75F4DB9D79731A3ABE50BC"
        ));
        let expected = decode::<4627>(concat!(
            "62BC12587195F9B5916CD87143510516532B415092707D95993B8EB560BD8E984982BFB9C2E11EC214104E75A0081E025342FB4C2A5627EF5E1982E6B13F799B",
            "2708DE38CE1D1B87167D0D15ED2625E373E5003B5137C749A1A14F0F85952694684B6BB9BEAF87E2EBFFBD537E45B46F2372CABCA9663FD499E4C80040C7B52D",
            "8EE6E31A7900B1D36B1FD6001E0A71A455B1A5AF65CA57C2D13F14559E9CE11CEBC918B8C68CC2500CEEA299112E2C210015CA773933DE9F2632AC0BA2F18EEF",
            "345ECD444E553ABC0B113D26273C8296ECF13A7BCB2A994C95242D24E83E5BA1D4598D1639CCD034245FCE3B710B13CD3DF19EFC9C142805AA83CDB6129046EB",
            "64D819C8D1814DED7994036FE6580D30F6CC41DEEBFAFA3A5714ED16438754E00A3821FD4CC9A2404F4CBC453DE6E32C4978BFB04D97AF236027DA9DBB3E2862",
            "3BA7280E101F2030D36148D66D86B3414F2788A2D94E72A40EA315017B296E6C7EB9290CE6C36207FE09B19AB25869B75F9E13BA92247B84E19BA3164092C471",
            "73520966F6DD7AA111EB4FBD43739D0F0F7D7087E1C6022A3BA99D7DB3C16C27447AC596306B72082EB94B18346572777A5BD3AFB1DA9F4A1E32FADCF2D8F5B2",
            "85F641EDAE4A17C908104952DE417E7D7106D71B855C1BC24A42922E4C23398EAEE54B1FF55CD45B466183925F3F1D40D9FC0ABA1AE70203ED92044F776C6E15",
            "465AF1AC2A605E6A123D918356F1048F0F499157DEC4075210E540D8F314E443EB50E0C120602E5479847CADDF2D14AFC440A6D318EEF39178298A16E5200513",
            "0B7C63FF1564346917B7E48D02D13AC24E1BBBED0609C28EEBF4134CC09AD343179BA7A9C54C48AC1F8173B9102E250501DAE91011C27B29D40F05C7B314C657",
            "1406FC02299DB974152407F0F014B5DE4132209E2570FEBDB1D65682B76944C5AAA296A4D3CE1D9C5751E03EBE7868FF71CDA682C6CF4F8FE199F4D74CB0F8E3",
            "4656C7B81933CB142B74C8D6108407B7CD80FE37EC37A2E347BE9D15BD6FCBA827AD3113AA4C296ADA7810B655801A80BA02A4A510BC35F3E0458F0CA19349A9",
            "B9B782207D0A5B749EB23F850F3C2460257F5EAFA6EC39068421BFE7CF2F3CC7103609ED7A055112A8E75DECB53AE77166F05016D9CA59A4A1F97240BC5687BF",
            "7773F61783CD5CE0E3C67EB13B13C1279067EE871C68D058C85025CBB68A2191860E0122891B3C12AE3944C8522892E4467A51D0A72357924167D9D853886106",
            "27A1D13FF8A272BE41E5BBFF247DDECCCC59AE73558A9D2838FC1CEF76607E623801D15E47793B3932C608DDD9DD0D3B14D0088B7DA1071602D8904C14BDC2A2",
            "CFA099EA7C2C4D424FFEDD34E097C8A5FE4E993F823D2FF14964214A9095F86769615ED8CE8C7C08B03AEF1C23D25584E4C98C16FD1ED3C59A5C2EF615E0CF72",
            "CD0B2CA4723365D6D007869B9FBAFC60968161D719406FE576F8042BB76EF7B662417731CAE2D619966ED4E8C9BA57E197CCFD8FBB4D115DEE1EEC804812A99C",
            "2BEB0950205BDD084E6330889011A9945E4576B7934BD1A8B79BDE64C491929F20BB7FE104F279F65536036D209F6A8A527DE4FF8FA299C227C065398E7372FA",
            "CDD099469EA76C5E75BC2DC2EFB97C33C4C09512F7F063A1323D705E55E03CEE05B181486A5E6ED24B3EDF461204080207D026D39C702336C16273983D638FA5",
            "6A898F9A1A547E87AAEFD6AEEE375A678D40CE0D112314612EFB0A51F64D702C825FABCA1900B7C9BB6689017F847628378BDEEA7051AD7EFDC40EDD6EFDC7BA",
            "36D37E77489780DBFB92F707AB98337E9736EECBEE9214CC0CFED6FE8EDE9CE09B0F0B134C6F2C93A9CA9A180E5366B4267DB0EA71E16D89FE8A975E34FEB9E7",
            "803ADBD673FFFD234467F27323B98C0C7A88C872CE7436359FB20D017BCFC9F7A202094C80400B44D6DCDC643EA6535C5400AD370B6FFDEF4D077374144C5B88",
            "8E7F02D4B6C4A59E2CCB79EE7E9C0AFA78BA88443E9BAB6F8187FE86F8C1146FBCEDA2063C19ABDAF4D679D9BE2617B14200CC89A5159C3088D4FAC35C3A9B80",
            "01BA0CCC29D0AAB4E22C57737F0BF9B4611B5768385ECD3640631578EE941292B11433DCC98FAFC0453E111E9DBD08C69CD5644443A797D03CF8557ABB789E3A",
            "518CFDB0C5B49D97D34ED633042EEE7871C10F2503906E9794D03D7BA6318D3DF69151AA54EF13BC18C557AB3F6B190FF7012766D0ABA7DEC09CF6CD7484A84A",
            "8B65F2D320D53F65A1329E1DE9B8E9CC33667D99BF58A29CA283289DA7D9189DEAA968BAD3045C6E5D803978683AFB3713D8EA047777A77F147E39F3F7C75B4B",
            "2589E57E6F58B9262F13025EB957F5AFE77085A3A8B8FDE883A12C7C0FAFA645A70ADA9CE62CF48D41B1982BCBEB56692FA4D6C19E223FC11EA6357D0ABDA649",
            "5C667A922E12C6F77DE8E5686C2FCC4FBF0192C76228E17F29D453FE2BFDE83FC7C20DE1C0F93D9AAA98BF76D3095BD1635B932CE1166C22FB935DC131DA562D",
            "EB03BB31A99C6F2088114E83A858E616A0B77442B1030847613B9E9F81AA93819EB874F711533CE90A987D0B59602DF6BAC07CB0A2E45D4A4578BC3CB4F3391F",
            "78551E8439896A583D295AB2180498A501E5D5CDBBDBBF874E17A6F2911CCA33A0E569606EA408A731C4D0A58205B4D88A323FA82BC0EAAFE1E16A2784CA8CDF",
            "5B5A6F47D82F0AA95ABE5DBA8F1BF7C5D3E8AF4E49785C2C3B25978291AF17FB83AF8BBCCF4AF191930AD4E9E05C3DE66CBA38C7343B5566420A21180E5BF5F2",
            "B48E444A461002BC18B2C584372ECEED104A702A79BB9948FD52F574222615E3E2555054B2FD1B43080006AC3202FA2BA6FB88529BD4BF741903470A91A78068",
            "6464EE4251FA2D0E123C26B731423F2A19205BA1AC0D5AA3FCAE14FACF690B7EAFD96C80B1799F77E96E769157521C7B89D6694EDBE9177FBFD43141DA165F5D",
            "A2D990997D1CA5B05471102A91DB717AEB47DE0D296C73C9D1D2774F5777337D0B26FED377B08AFD3971773FBFB4BD8B1BE2863C840DA1BED85D22EBD2F1419A",
            "0F139EA13E0868188216FE89BF182FF3139DA3132071118A5CE51C7B511C09E78077A9B4A2B86AB5380B65E6B9DF9E50751BC7F90F208E0AE28B326085C50C8E",
            "84AC4E60040C367D6BA7BA1E239FF9D7B662AB9F01DF7A0F3328A4A0E2F6E13133485DF9365F5989A73B3FDB0E2129E1DD0206C575791767347D7BC78D45C69D",
            "060D225A8229F547FD9261829C671F365770838EA2B71F7F7F093334D27842D67ED2EE79F3933465D386E7E1346CA5F42041017DBBA7320783A4AF0D4585F228",
            "D73FBACF7CDD56A26A7AB18AEBA0C8814D81BF145208A375B1E461A0BA3F5C09BF71BFBAF069779989468E7B1868B27960957DE87000F69409625F797BD13D84",
            "736EA2EC790227B8DBBA58E674D45195B6C73109A98AEFE007214CD6E6DD7731D2F7F6C7DA6DCE72F52E8343DC6FC5EE3ECF5333EDBE75E5604E16FC4A445D41",
            "80D4993B99F51C54D583DAD891E82C6D8A99227BB2DF7D4282F09D2632850C371E04687E8580BA8B087E9C486FA9E896FAA6B2D55D8B45FBA0D7301BC204D369",
            "54053D803D5460A315B5C72BC0A344C3A80932F3E26230A4E2A6A315DF3BFF65EB449F274BB5E0544D4CF39CD40579F2B22F1B2A76BDCB9191B84498ED08FBC9",
            "11036776A9CD8F7AC3DB067F09D6E1CC0190EE8410A1636ED405A3753CE0BD74FA2C0CD7D3627FF7805DA5F7D273B1534140B3BB06F7686A5703F48C85A450D4",
            "5C29C896F99DE6C0685BF70E5397ABBCC5A026B31B6EEDB38DB5E284E1C71CCF8196254689FB5496A9B9939A2F95794F8EAE41DE35D60F7468D96172244F3EFF",
            "EB7495D5247F80FF2B9B2C19371A0B958113E94D35DFEFDDF4EC9933FC9A993DB9614D80C3F4F9C643C6DC0DC337BA660E0D1D5FC92B5B0C72935258050C5148",
            "35398A8C9A4A485CC135B4381FA24B94B52F64B850D6A87DC523F564FB90C1C04666F73AAA04A8701661CED3903D975798D2D3CEB80BDBCCB2C46783C4A83B3B",
            "47FC4274BF9291393364F382F86DF9B37626ABD24F4AB3DBB405D1E3149DAE44298120CED5A411609DD986C4A28211D374F29E73207A9D861BFA6A88C768E637",
            "E0B970A82DAB639AC615570733B623B0AEF74551DCB8D18792F43FD88CEA7FB15A9ED0FD73C06634C937C23D7AF0EEAB5A5F8145BD50D85444631608B94A8B52",
            "688D254AEBC1862E5A021FB947654ED1D64AA96B0F99AAF0FF257FB44673B5A4F8684DA85A4AA9E95DD48B4AFAA2EBDE15F1501C1DC85760A4A10D0957276EE2",
            "8EF888CBFDA5B4AA3EFD275DA37FDA8B464DA19F3D37352AC51BE6A4427F28C03FA293B0B0F788C95D3BE897DCE1C9D5D9D05C934D8E1CD9B632E0F1402D0FE4",
            "9906B554EC2A049C917717014C498C877F205F6ECB9C893C06CD6C6EF1C8C97232A66FC225456EFD420E88FF0FC990CF9C33EC2DD46646160E7FC161ED47678C",
            "B621E5DFCE927CFB0B179BB5100FAAE72B754A226263E43623A3BD6CBAB463BF08B7ECD586EA9F83F23B962ACC6A55C7432604C194AC51595FA9CF2586AE97F0",
            "FC944584EAF093A0C3FC13E97D6F9CCEDFA5EE1FDBA2CDA9ED470B4D33C152C7E976497A6C4151002965F680EAE5F6799C2EDE4C500BCD84BC4C87536099E34D",
            "9119C338E09CDE25645CB4EA27B4B37ED3C25E03275E24CD1728F74E97C741F3AC62B6B630468B6DC4FBDDC12442BD3A56B34012B0D4738EC6955D42BF100F93",
            "169D30A9304E0C84F4F0DEBA2E0581FE841881EB46C472464BD439172F69247B666A2412357A354186D0EA666A794BB1A1C5D9F07D7C3379AFDEB4BC69007989",
            "A439C579D6C0F1745986DACB4377F8AE53932B371BDD516C7F0EE54B8B1DB1D62DD0E52877AFFC4A0447EA9CCD95B7C9071D5199003C62A876E86C073875CC57",
            "092858EB17046230842AB03837E7AB231B598A7FC76279748A4EBAFF57B82B79F943342899007B5A8B48F37AAFE8F27EE8FDAC2DB4EE2487135898BB3BF74A9A",
            "B7064A1D1BA90228442A9C8BFAB270B757CC9A45329E1F8121B5CA7A6F6E126C2FC482FA611B41D6202BB9ACEF21438A7CA6675F032570886B8AB58BB00378DD",
            "DE638E235C4D39A6E155664B3D62A2A9CADE3A93A4DB88DFD8E7C7CD22EC083ACEE60196423581FAFBF2517EE1C3B6BB388342DEF68E668A5DFF51CF20F4076D",
            "B07747738B286B67E02185E8C940441B1A5462C382CA27E30FAC30355EF49FB5158782B175538703A0A5214515ACBD8B38F9333071B43536CD7F658D09F869C9",
            "FE6FCC01AAB35F125B5E725F0C7EC563CB85A9FB66EFC3C01D53EA412D093A6B9C5A98B5BE259518BEC274FCE6BA9CE4EAB13C457A209A5F9151EF4AF36D4838",
            "8ED42135E8928EFD603E521C280342F20504D011E6C94AC4B1E922E00212F42032E3F8D809E9283D0D173E3EB31D599BB7A50AE3586996D9D837267D3E66DCD5",
            "397FD2D757D719C5FFD3FCED33988F6A9F878BC2C59DA0FC1A2695E4E110E05FC785018B91BB64E17287254D821CE61E3CAFCCE42616A23E2CB61442877C66B3",
            "ADCF999304AA5547FDE2825E32608E76DD09E5DB429B88F45CCA86830E46A255F75BBC3245493636E1E7A84FD5060C782402723F9CB62813C082E3B49F2479DE",
            "B9AF0E2A6C1D442E2E5F73E4549B7D6D86CF96090237B93C902C6AD977C7960A5D3B6844EE7AB3EB9C127220CD8B8F9F4279C8EC263D620845AD938BE0B7AFD9",
            "167FBE28EE5E9EE13C21DE4F5C3EBFF3EBF821E28A546EE1088FF42EA1726F3A402E069787D0B5B41B060513DACD3D35569BFD78C8C21ABFCDEA4C562F6B0FCD",
            "D97581EF33C37DF6892F7B61D67FF36CDBBB87B5FD654253E7DE82ACBD60B00C13B9B78207ADA39C5D3B9B2FE098ABB0725D706E260676ABF25EC608E23D9E96",
            "D4D1910DCBAA08555852A6C0C761D52DB4763C6502139FE881009B0B4990C17669E4800FA7A733475A8E3E0328101ED8F2F4D7397358BACC48E36761821BA7FB",
            "E86BD6A22BB752DF29A83F26C51A220ADBE3CD223413C0E54874E60F684949E3D0E60BE79BB5553B9E428A4F7B4703FDB2330E45FD58B375890B8A1609044525",
            "3BF59AF2E3CDD29B442A4229E6822FE909E37C02CD7E20221049FAA1AC5777416C3EADBA5B2E1427FA95CAB99A8142236215E47837301CB1310F79EDA18646DA",
            "FC30E89ADAD7B35B7F74519BAB20E5E3A3FA754DBF03D4BFA9DED6220B5B7726A82070397EF2EA1C3CAED8C95440E79F67AC0E944F810CEE7B39C721DE5FAA20",
            "7375F4FB12ADAE9AAF87D85806861B72FE2ED1FE0AB85A5E61440C14901F56DD1EE8093B6403FF13ECDBE576F41C2EB0EC2B9690D8BC0A517A8B22321C01EC84",
            "4C75859AEE283D7679AAC3D1D9E417485D6D797ADEEDFEFF2F3B4885A5FF0F2A3334395C82879299D3576AB5DFE60C26363F45949DFB172746C7E9F000000000",
            "0000000000000000000000050E181E292E363C"
        ));

        let key = MlDsa87SigningKey::from_seed(&seed);
        let mut rng = FixtureRng {
            failure: None,
            position: 0,
            bytes: random,
        };

        let signature = key
            .0
            .expanded_key()
            .sign_randomized(&message, &context, &mut rng)
            .unwrap();

        assert_eq!(rng.position, 32);
        assert_eq!(signature.encode().as_slice(), expected);
        assert!(
            key.verification_key()
                .0
                .verify_with_context(&message, &context, &signature)
        );
        assert!(
            !key.verification_key()
                .0
                .verify_with_context(&message, b"", &signature)
        );
    }

    /// Test only entropy source exercising each reported signing acquisition failure.
    struct FixtureRng {
        /// Byte position at which acquisition reports failure.
        failure: Option<usize>,

        /// Number of bytes written so far.
        position: usize,

        /// Complete synthetic signing bytes or the public NIST entropy fixture.
        bytes: [u8; 32],
    }
    impl TryCryptoRng for FixtureRng {}
    impl TryRng for FixtureRng {
        /// Fixed synthetic acquisition failure.
        type Error = std::io::Error;

        /// Reads four bytes through the fixture source.
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;

            Ok(u32::from_le_bytes(bytes))
        }

        /// Reads eight bytes through the fixture source.
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;

            Ok(u64::from_le_bytes(bytes))
        }

        /// Fills predictable signing randomness until a partial or final failure.
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for byte in output {
                if self.failure == Some(self.position) {
                    return Err(std::io::Error::other("fixture failure"));
                }

                *byte = *self
                    .bytes
                    .get(self.position)
                    .ok_or_else(|| std::io::Error::other("fixture exhausted"))?;
                self.position += 1;
            }

            if self.failure == Some(self.position) {
                return Err(std::io::Error::other("fixture failure"));
            }

            Ok(())
        }
    }
}
