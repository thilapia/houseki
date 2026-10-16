use houseki_types::EncodedMlKem1024Ciphertext;
use zeroize::Zeroizing;

use super::NoteEncryptionContext;
use crate::{
    CryptoFramingError, CryptoSuite, MlKem1024SharedSecret,
    domain::{Domain, Frame},
};

/// One operation's protected key, nonce and the associated data used to derive it.
///
/// No cloning, formatting or serialization of this internal material is exposed.
pub(super) struct NoteEncryptionMaterial {
    pub(super) key: Zeroizing<[u8; 32]>,
    pub(super) associated_data: Vec<u8>,
    pub(super) nonce: [u8; 12],
}

/// Consumes the KEM result and derives V1 material without exposing secret bytes.
///
/// The suite's seal/open callers must pair the secret with this encapsulation
/// and recipient key. Derivation alone does not verify that relationship or
/// authenticate a payload; implicit rejection also yields derivable material.
pub(super) fn derive_note_material(
    context: &NoteEncryptionContext,
    secret: MlKem1024SharedSecret,
    encapsulation: &EncodedMlKem1024Ciphertext,
    nonce: &[u8; 12],
) -> Result<NoteEncryptionMaterial, CryptoFramingError> {
    match context.suite() {
        CryptoSuite::V1 => {
            let associated_data = context.associated_data(encapsulation, nonce)?;
            let mut salt = Vec::new();
            let mut sink = |chunk: &[u8]| salt.extend_from_slice(chunk);
            let mut frame = Frame::new(Domain::NoteKdfExtract, 2, &mut sink);
            frame.part(context.transaction_context().network_id().as_bytes())?;
            frame.part(&context.suite().id().value().to_le_bytes())?;
            frame.finish()?;

            let mut info = Vec::new();
            let mut sink = |chunk: &[u8]| info.extend_from_slice(chunk);
            let mut frame = Frame::new(Domain::NoteKdfExpand, 1, &mut sink);
            frame.part(&associated_data)?;
            frame.finish()?;

            let key = secret.derive_key(&salt, &info);
            Ok(NoteEncryptionMaterial {
                key,
                associated_data,
                nonce: *nonce,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EncodedMlKem1024Ciphertext, NoteEncryptionContext, derive_note_material};
    use crate::MlKem1024SharedSecret;
    use crate::{
        CryptoSuite, MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, PaymentEncryptionCore,
    };
    use houseki_types::{
        Amount, CheckpointSequence, EncodedMlKem1024PublicKey, FeeScheduleId, NetworkId,
        NoteCommitment, NoteRoot, Nullifier, PaymentCountLimits, PaymentInputs, ProofProfileId,
        ProtocolVersion, TransactionContext, ValidityCheckpointRange,
    };

    fn context(key: &MlKem1024EncapsulationKey, network: u8, fee: u128) -> NoteEncryptionContext {
        let limits = PaymentCountLimits::new(1, 1).unwrap();
        let core = PaymentEncryptionCore::new(
            TransactionContext::new(
                NetworkId::from_bytes(std::array::from_fn(|i| u8::try_from(i).unwrap() ^ network)),
                ProtocolVersion::new(2),
                ProofProfileId::new(3),
                FeeScheduleId::new(4),
                ValidityCheckpointRange::new(
                    CheckpointSequence::new(5),
                    CheckpointSequence::new(8),
                )
                .unwrap(),
            ),
            PaymentInputs::new(
                NoteRoot::from_bytes([9; 64]),
                vec![Nullifier::from_bytes([10; 64])],
                limits,
            )
            .unwrap(),
            vec![(NoteCommitment::from_bytes([12; 64]), CryptoSuite::V1)],
            Amount::from_atoms(fee).unwrap(),
            limits,
        )
        .unwrap();
        NoteEncryptionContext::for_payment(&core, 0, key).unwrap()
    }

    #[test]
    fn complete_suite_key_matches_independent_framed_hkdf_vector() {
        let key =
            MlKem1024EncapsulationKey::try_from(&EncodedMlKem1024PublicKey::from_bytes([0; 1568]))
                .unwrap();
        let context = context(&key, 0, 17);
        let encapsulation = EncodedMlKem1024Ciphertext::from_bytes([0; 1568]);
        let material = derive_note_material(
            &context,
            MlKem1024SharedSecret::fixture_secret(),
            &encapsulation,
            &[0; 12],
        )
        .unwrap();
        // Python hashlib/hmac with the specified core, AAD, salt and info
        // codecs, plus the independent recipient-binding vector. Synthetic
        // material tests the codec; honest KEM pairing is tested separately.
        let actual: String = material
            .key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            actual,
            "707cf5dd633235fa4ab8841cb748694b36b5c099d378dbb43a358c319a369dbf"
        );
        assert_eq!(
            material.associated_data,
            context.associated_data(&encapsulation, &[0; 12]).unwrap()
        );
    }

    #[test]
    fn sender_and_recipient_derive_the_same_key_and_associated_data() {
        let recipient = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let public = recipient.encapsulation_key();
        let (encapsulation, sender_secret) = public.encapsulate().unwrap();
        let nonce = [23; 12];
        let sender = derive_note_material(
            &context(&public, 0, 17),
            sender_secret,
            &encapsulation,
            &nonce,
        )
        .unwrap();
        let recovered = derive_note_material(
            &context(&public, 0, 17),
            recipient.decapsulate(&encapsulation),
            &encapsulation,
            &nonce,
        )
        .unwrap();
        assert_eq!(*sender.key, *recovered.key);
        assert_eq!(sender.associated_data, recovered.associated_data);

        let other = MlKem1024DecapsulationKey::from_seed(&[8; 64]);
        let rejected = derive_note_material(
            &context(&public, 0, 17),
            other.decapsulate(&encapsulation),
            &encapsulation,
            &nonce,
        )
        .unwrap();
        assert_ne!(*sender.key, *rejected.key);
        assert_eq!(sender.associated_data, rejected.associated_data);
        // Implicit rejection still produces a key. AEAD must authenticate it
        // before a future opening operation can release any plaintext.
    }

    #[test]
    fn kem_kdf_and_aead_recover_only_under_the_original_inputs() {
        use crate::suite::aead::NoteAeadError;

        let recipient = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let public = recipient.encapsulation_key();
        let other = MlKem1024DecapsulationKey::from_seed(&[8; 64]);
        let (encapsulation, secret) = public.encapsulate().unwrap();
        let nonce = [23; 12];
        let original_context = context(&public, 0, 17);
        let ciphertext = derive_note_material(&original_context, secret, &encapsulation, &nonce)
            .unwrap()
            .seal(b"note", 4)
            .unwrap();
        let recovered = derive_note_material(
            &original_context,
            recipient.decapsulate(&encapsulation),
            &encapsulation,
            &nonce,
        )
        .unwrap()
        .open(&ciphertext, 4)
        .unwrap();
        assert_eq!(&**recovered, b"note");

        let wrong_secret = derive_note_material(
            &original_context,
            other.decapsulate(&encapsulation),
            &encapsulation,
            &nonce,
        )
        .unwrap()
        .open(&ciphertext, 4);
        assert_eq!(
            wrong_secret.unwrap_err(),
            NoteAeadError::AuthenticationFailed
        );

        let mut changed_encapsulation = *encapsulation.as_bytes();
        changed_encapsulation[1567] ^= 1;
        for (changed_context, changed_encapsulation, changed_nonce) in [
            (context(&public, 1, 17), encapsulation.clone(), nonce),
            (context(&public, 0, 18), encapsulation.clone(), nonce),
            (
                context(&other.encapsulation_key(), 0, 17),
                encapsulation.clone(),
                nonce,
            ),
            (
                original_context.clone(),
                EncodedMlKem1024Ciphertext::from_bytes(changed_encapsulation),
                nonce,
            ),
            (original_context.clone(), encapsulation.clone(), [24; 12]),
        ] {
            let material = derive_note_material(
                &changed_context,
                recipient.decapsulate(&changed_encapsulation),
                &changed_encapsulation,
                &changed_nonce,
            )
            .unwrap();
            assert_eq!(
                material.open(&ciphertext, 4).unwrap_err(),
                NoteAeadError::AuthenticationFailed
            );
        }
    }

    #[test]
    fn key_derivation_binds_network_core_recipient_encapsulation_and_nonce() {
        let public = MlKem1024DecapsulationKey::from_seed(&[7; 64]).encapsulation_key();
        let other = MlKem1024DecapsulationKey::from_seed(&[8; 64]).encapsulation_key();
        let encapsulation = EncodedMlKem1024Ciphertext::from_bytes([0; 1568]);
        let original = derive_note_material(
            &context(&public, 0, 17),
            MlKem1024SharedSecret::fixture_secret(),
            &encapsulation,
            &[0; 12],
        )
        .unwrap();
        for (context, encapsulation, nonce) in [
            (context(&public, 1, 17), encapsulation.clone(), [0; 12]),
            (context(&public, 0, 18), encapsulation.clone(), [0; 12]),
            (context(&other, 0, 17), encapsulation.clone(), [0; 12]),
            (
                context(&public, 0, 17),
                EncodedMlKem1024Ciphertext::from_bytes([255; 1568]),
                [0; 12],
            ),
            (context(&public, 0, 17), encapsulation.clone(), [255; 12]),
        ] {
            let changed = derive_note_material(
                &context,
                MlKem1024SharedSecret::fixture_secret(),
                &encapsulation,
                &nonce,
            )
            .unwrap();
            assert_ne!(*original.key, *changed.key);
            assert_ne!(original.associated_data, changed.associated_data);
        }
    }
}
