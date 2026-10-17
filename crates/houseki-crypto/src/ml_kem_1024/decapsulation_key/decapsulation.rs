//! Shared secret recovery with ML-KEM-1024 implicit rejection.

use houseki_types::EncodedMlKem1024Ciphertext;
use ml_kem::Decapsulate;
use zeroize::Zeroizing;

use super::MlKem1024DecapsulationKey;
use crate::MlKem1024SharedSecret;

impl MlKem1024DecapsulationKey {
    /// Decapsulates an encoded ciphertext into a protected shared secret without randomness.
    ///
    /// The encoded type enforces the required 1568 byte length, while key construction ensures
    /// a generated or seed restored private key.
    ///
    /// If the ciphertext fails ML-KEM's internal consistency check, including when intended for
    /// another key, implicit rejection produces a fallback secret without an error or validity
    /// flag.
    ///
    /// The result feeds Houseki's suite KDF but does not establish successful recovery or
    /// authentication, so the complete suite must authenticate the payload before releasing
    /// plaintext.
    pub fn decapsulate(&self, ciphertext: &EncodedMlKem1024Ciphertext) -> MlKem1024SharedSecret {
        let shared_key = self.0.decapsulate(ciphertext.as_bytes().into());

        MlKem1024SharedSecret::from_backend(Zeroizing::new(shared_key))
    }
}

/// NIST recovery vectors, implicit rejection and KEM agreement.
#[cfg(test)]
mod tests {
    use houseki_types::EncodedMlKem1024Ciphertext;

    use super::MlKem1024DecapsulationKey;
    use crate::ml_kem_1024::shared_secret::{assert_secret_eq, assert_secrets_eq};

    // Public NIST ACVP seed-format decapsulation fixtures.
    // https://github.com/usnistgov/ACVP-Server/tree/ad33b3d9504491767f1aa76382464f3b3fa2359e/gen-val/json-files/ML-KEM-encapDecap-FIPS203-tr1
    // Seed order is d || z.
    // Case 116's published result equals J(z || c),
    // exercising implicit rejection.
    // Case 118 recovers the encapsulated secret.
    // tgId 8, tcId 118.
    /// NIST seed for the valid decapsulation case.
    const VALID_SEED: &str = "dc90b0495ef0b1baaf01ec0668f53c6fa270c088e37ef7bb98ee8101e9031bca40fcdaeb265ee60e5ed7c1623000abd32bbda5f7f51d8bb67bd6a844fe0f9170";

    /// NIST ciphertext accepted by the matching private key.
    const VALID_CIPHERTEXT: &str = concat!(
        "928864d15d172aa6ac24c496fc376f8c8743270b0e74f764055f2ea60ff74d1004630698aa2beea9f4590febf63655c7",
        "10e9ccce4d9bb5e660b9078c28c125a297edae5d792c2db5e930ccbf88f56bbfcc0cc46d71ad8faa26a910b74892467b",
        "fec0045b37c679a6c823fc4c802eb7df2606d1f916f74da6206b3ca852e1f9438c3732fe903a392459209c9b8c7b9a85",
        "9b774f0c7a66f715452c8814adf37333d522a678616023136cdf704d6912bc905c8ca946c0d04f7e7bf862017f8ac4f6",
        "eac8d91f7d29e97654d27da3faa43077e8dd0917f56bc75095df4baf324882c999c0abbfcd71abc0c723b8f0f4ebed4a",
        "239bf02b28387a0442973eb6d617da1150579ff9b7bf0c09e78042bddd8cb4daf58980f1e73581860bdbc0af16935c32",
        "0312d5e1a0f6315665d0ea78ec4b7a4524c64ca06bee7fb1e75bad83120b30188a35acf92bbdbf66090dc1fef7e7bbd5",
        "9dbb0fbd76f9c6e330428bae4aaf7b93e4200b28bd7b7922343af8a579d1a3c458b5a05d86abe6e237ebdd256bf37a34",
        "89dedfd54716aca3d8e689399d53c9117892613a406a741156475d8a50c46119ea291798a0270be33deca2c77a69ac9f",
        "17dd6a8261ab7a9cd0925cb6c5da163f13414a65283f9ad94d8e2a2e213fb468c79871061734670184edea951a682f20",
        "37d2b984f4dcaa7a942186a154ea1fca82ee07b8a7a0216b7096a5f7feb368f2b11ac580486b3344a719cc8aafd7e367",
        "67e3418d846de17027d4e0e873346abc788b37dd5f7481b2332877fd97c34f7a24af5e4db5504365c4f83c05ac0d8a6f",
        "833dea6aeb4f2cd1a086c2348f0a6c09fd327f0fbdfdb41031293892d93a6be9cdde32d0ab11a29cbae5132a5f31b847",
        "598581c49a43bd3ed44c04ff352ef9f0fc365531d77996b614ed5fadcbef08448def7ac9b1476032ff5e9e01664d3730",
        "80a8ea2b49f06b47453045d25b12f16b79d504524f25f893f802bf5f366fed5550c329d69be8c0bc803118e7aefa69d2",
        "bdda081d3be1c2ada8af19d1cc97c51c996d014c76a3579246fa4781047daea53bc4f1b1bfaa2e543956cfe607b6d044",
        "ccf564902534e3ac0c22113d2365428de364aef3c693f67a6dddb408fbe473f1de06335b060319f6d823137af5a725a1",
        "06c2f02841c93277078d58db3d9a161aad98ac9f2a00e3bd950b65f23a7328e294c3e4d02d40d081330935f9417e60cb",
        "b2a147a6f3a6e7ab7646f69f06a2b5a1ced00c1570e300c8ec0154e2fab3163751450f4fb89b74d10c17def16caec89c",
        "342abcbc699e1f9e28eb72a838a7e85fe97e7d7dfc61a97fb97b13fed0cabf44e5999b1ac2d1f69ba6ad43b3dcbe5453",
        "3049934c1905027942a150af8421d269a28a3cf5139edf3f1bc1646206f8bbb20aac62b7fe78f4d189058b5ed0d039da",
        "41ba5e87ed8896ba18d4b793bd838442f1fab2fe4c79449766196820118411f174fdf7e7e741972822e4a6acf0d7139e",
        "a2b7249e9ec2073669c0ea6bbe0485aee1fb5c1baf98a220d5e9a31b0791e0ea4c513c9006f99c6e14c0d3e8e8a22d9c",
        "56037761d8f9e690ba7c1abe5656ba486c78167a80954da812b6f07d5c5ee07444f9ff32f585b556e395952b6f790271",
        "15079c5b1316a33290898b68d85d115da91124b85420d2f5cebbff7c8e4bd38d71c306cc5d3bd3a5570a59fcb5156aa0",
        "75002859b11baa67de840777b305ef619c534247d346dd7953b8afea8cd388bfc4c0ae2a5ae83c34f5c672a83a7d5e46",
        "2e9fb676e0a3a6a691c22a8c27415889c545b3b305d35cd5c796fce12fafe8ea018e8b798cf77309575e9480e76bf921",
        "d0c745dcb86671b6c43067bfb56dc4292c5107bc01c98f5fea2903df8aa6c9965078956a432a3e0fa3be6bc1298fe9b7",
        "4c56033bafa70790fd1a0f2f0a877c63e3c2b35304f3932556fb2f472a2ab11afb1251e4935180d65c59dab1401faa2c",
        "d9961419ceb04ca94172137f2ca51b6d65ee2f3e4969f2b401da26e48751329f38b200addd27f2e11a07093467a26173",
        "c477782a2d7c5b5452af12463e3bef1815848e72a29b286c7ef46b85b8965ab738c6ef8bec98d0cbdb7b381c7d517f41",
        "44ea15efa8458652dee66c0cbb1883844f92f06fab633f7716a5af9658bc4023a96e92809cf93c7cf24721d83d3c8ec1",
        "2b62c2eb6478a67d403c63d54f6bb807f18145d8a722a7ab6be94958ad3d0f45",
    );

    /// NIST expected secret for valid decapsulation.
    const VALID_SECRET: &str = "fac11276b8629a5be2fdd4b523a3bf3d25bd078b20603f3a2655d8d2e8cff6a2";
    // tgId 8, tcId 116.
    /// NIST seed for the implicit rejection case.
    const REJECTED_SEED: &str = "74ae40cf70f181a17e1abcc49e8f96ac089d68fc17ef8e0e22563afea3298890716928c1b17b00bf7eb728a453070196bd725cc3e2b82e9c6ff24b71b00059a6";

    /// NIST ciphertext that selects implicit rejection.
    const REJECTED_CIPHERTEXT: &str = concat!(
        "c91507183411e16b8cb7ae6b6478fef375fb41517cd916d8e175d9d16d1bcf71185758265365f20013085435227521f8",
        "d9406e06ca68d948929f34b25fd69acc5a7597cd3fa034b44476581b67286bdbe3f058a9fd0e19aa6390485956d3af46",
        "84e8635c3331705f0591d9a217d8ba367f17431b83ccd1e92cf28111f6d61c791963149b030e858ede1e171de91820ad",
        "f6b6f0569d716bc6ac5271b0014ce9a656c4726ec9be3673fc3c4a7c5ee04ad8397c8827fc68fb932d51574cffa0fff3",
        "2c26317ee93c2ce85a99976fc4d47f414594f55aae09e08f066293250d7d777d54716d8b9b335f583bccfc3a816ba671",
        "3b14a51d2b8d9980bddc770f43c1de9347bd9c8b38c3a36e19bd7d8a651a739a5bbb0160d6ddd4b303ff9deff568fc1f",
        "c3cd7076cf1d5e7fe3bd08ff5159d69afb647104cccaf072a5002164f2d5a92f79b7012fe1c2c27998ffc9e4c908e37c",
        "217fd7d106b47539f9532da87a1fda4289ed0a3d40551fe6c34aef1306d946412bbe911e45dd09f2338a89ce94fdbf80",
        "7b089e6f70b11bf847ffc72c2365d1d572fc6328e2e64840e2fb0dd05968dad4515e09dbb9cb9ccbdb7dad612443583a",
        "3ef91b0b2f30ab27b0a43e5c434ff588de5e42cac0281d6c0050d3bca93bdab8353bd8cc6a1e84456b95fe2992ce1f52",
        "9376725642cc46ca9ab895a26e6a95c17d9acdd963716ccb9f513ec0efca10aadfd35a2ed3909ce97baaea8b910b6a8f",
        "7861fe4f888ffebc008d00d1dbea4976c245ea45c90705cb92c5679c73e790506d5b7ed990eb0db166144bfca9ab55c3",
        "2005c363d484dcff647ddfefdbd4680797063760f8cedd672b41595d3ddb70b70c9af9a58aaf4a7a01b7a1f7ffc01218",
        "2266a547e1f42d4c0da8206b07c7f802a729a497fad08f5f6037b698da9a974b37afa115fe4bce0c25a022f1e8b99415",
        "f59da8cd963f490d17a34770e41ff1b982d5091fd8ed69c6b97864c812ad179536749aafb3a01718c38fea418f05921d",
        "dca8a6b076085109c4253aa28a4a3eb32842f8d109d894927567582ad9a950d2c392bc3a4577ef256b040baeecd07e7c",
        "3600ca39782ea6884e51e4d510ba7b3a649ef2de8a32c4b275cf375cfbc59823b3fab6edf2655ea1a964e68a07490c15",
        "a0e3301e7cb4a60b519cb5232b14c7f507e113e27eae7a7d19cf3317480de3d1ff94fa26e56aea31a19917ad4d5283b0",
        "dc0669af7f073a103715e1840a21008be0b4e6be24bfd2cb3742462f5856c36239cce9cc75ea02a8153f95156e0f52b3",
        "5dc035ef30c784a2c0b4ef50acb46c7eed77334f535185f91ec01ed69e3aef3dbb35f39f2622a5957fa34b41f4a83341",
        "fdc7b5d52962d8f1b2b9d32b1b8726143a20fea646984a82cd61c5a018b5552361cae466dbd515c7a7ea8ac5d3cf7912",
        "6b133e65e1b26868072b816312b258c28b6c9bfd6f9ec2c279bdf12c29547decf3b27fc23575bc35d458b0b6f4138429",
        "ac151a45b1cb0f3daa4df992b800e7038e919dc6cbcbf4f5f32f3ce75582e6a21d2ba33b412ab3dbad7c9dacfb4a1800",
        "173f4f9681a61eefeb1cf872db459db4240f4d51fe05fbc438371cfa5c912f407ccbf4e056a2911f5a4c4a59a8ea2971",
        "04b44076ac5c4f634e021dbd46f622688d356570f4a729ab4950ab1523f4b52db113d63481fea8fc6482878c8b374e4c",
        "aa958f5c6fd14a04616978d6e1da6941760e1c277dae24838f8b35c06aeeee51ffde4a996983dafad4ed5619fb8feb63",
        "eb59aa5c2dc59889c3f468822b0fbe0a3fa55bea7f2c3555b4ab60d055ebdead2b9d5e5777879cdf5fdca78fe319db87",
        "54fc28aeba1f7dbdb397e24c97a4fffb9c31e838f8921dc09dc7e845d638d8b71ccc0beddc6b7d7dfbf49b35d5a486dd",
        "b45efc47db154e574f69c1150c04e93a5a9874458bb625925007bbe28d36f9c5bdab8be7eb86cb6ff849d100504df62f",
        "1309395c8cacef8730566c78b3e23a9caf656ab5e4f7368e17fdc7c477d5af9247d38022647cb7ab959c07073cd49d67",
        "067d11943b06acadc0838d92ddfe29884d88c78ae4c68d6fd33b89d12ac9cde91b77324b258e736f62bf4014dba3d2e1",
        "fb5fb18d90a0a7191eca6d2a9bc774c8c87f8beb6d228be2e28dbca736c51ae43d9a5c24a817882416d75bcab1de0ef7",
        "597fef80848eeafc463857693b39a9c0103f1026f6c9c47c81d6e05c6215e02f",
    );

    /// NIST expected fallback secret for the rejected ciphertext.
    const REJECTED_SECRET: &str =
        "d883d6ccbba2f85c2d7acf5f5e4ccda345c17ab43ab768c51cb1a4c63eed3596";

    /// Decodes a fixed length hexadecimal conformance fixture.
    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);

        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }

    /// Checks recovery against the NIST valid decapsulation vector.
    #[test]
    fn decapsulation_matches_nist_shared_secret() {
        let key = MlKem1024DecapsulationKey::from_seed(&decode_hex(VALID_SEED));
        let ciphertext = EncodedMlKem1024Ciphertext::from_bytes(decode_hex(VALID_CIPHERTEXT));

        assert_secret_eq(&key.decapsulate(&ciphertext), &decode_hex(VALID_SECRET));
    }

    /// Checks the exact fallback secret from the NIST rejection vector.
    #[test]
    fn implicit_rejection_matches_nist_fallback_secret() {
        let key = MlKem1024DecapsulationKey::from_seed(&decode_hex(REJECTED_SEED));
        let ciphertext = EncodedMlKem1024Ciphertext::from_bytes(decode_hex(REJECTED_CIPHERTEXT));

        assert_secret_eq(&key.decapsulate(&ciphertext), &decode_hex(REJECTED_SECRET));
    }

    /// Checks the fallback derivation after ciphertext mutations.
    #[test]
    fn changed_ciphertexts_produce_exact_fallback_secrets() {
        let key = MlKem1024DecapsulationKey::from_seed(&decode_hex(VALID_SEED));

        // Independent FIPS 203 Algorithm 18 fallback oracles, calculated with Python
        // hashlib.shake_256(z + modified_ciphertext).hexdigest(32).
        for (index, expected) in [
            (
                0,
                "e7d08ae57381d3a4cd7463b266fdbff349205365cbc47ab73302d9e7afd1bd59",
            ),
            (
                1567,
                "713a667d8cf83a5ad5f7ef01ad47b736de35adb94a8754f2a3ff4f7a95242969",
            ),
        ] {
            let mut bytes =
                decode_hex::<{ EncodedMlKem1024Ciphertext::BYTE_LENGTH }>(VALID_CIPHERTEXT);
            bytes[index] ^= 1;

            let ciphertext = EncodedMlKem1024Ciphertext::from_bytes(bytes);

            assert_secret_eq(&key.decapsulate(&ciphertext), &decode_hex(expected));
        }
    }

    /// Checks the fallback derivation under a different recipient key.
    #[test]
    fn wrong_recipient_produces_exact_fallback_secret() {
        let key = MlKem1024DecapsulationKey::from_seed(&decode_hex(REJECTED_SEED));
        let ciphertext = EncodedMlKem1024Ciphertext::from_bytes(decode_hex(VALID_CIPHERTEXT));

        // The same independent SHAKE256 oracle, using this other key's z.
        let expected =
            decode_hex("97aa7b9c23e6c94d2191ee2e9b28e557c7a8ff9e5308a4100fb3e529469ac807");

        assert_secret_eq(&key.decapsulate(&ciphertext), &expected);
    }

    /// Checks agreement between public encapsulation and decapsulation operations.
    #[test]
    fn public_api_round_trip_agrees_on_shared_secret() {
        let key = MlKem1024DecapsulationKey::generate().unwrap();
        let (ciphertext, encapsulated) = key.encapsulation_key().encapsulate().unwrap();
        let decapsulated = key.decapsulate(&ciphertext);

        assert_secrets_eq(&encapsulated, &decapsulated);
    }
}
