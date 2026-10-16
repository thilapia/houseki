//! Bounded recovery of authenticated note bytes from complete envelopes.

mod error;

pub use error::NoteDecryptionError;

use super::{
    CryptoSuite, NoteEncryptionContext, aead::sealed_length, key_derivation::derive_note_material,
};
use crate::MlKem1024DecapsulationKey;
use houseki_types::EncryptedNoteEnvelope;
use zeroize::Zeroizing;

impl NoteEncryptionContext {
    /// Opens an envelope into guarded plaintext after authenticating it under this context.
    ///
    /// Recovery must reconstruct the context from the completed body's typed core and resolved
    /// output suites, using the recipient public key belonging to the supplied private key.
    ///
    /// The active inclusive `max_payload_bytes` limit covers the suite header, nonce,
    /// ciphertext and tag, excluding the separate encapsulation and outer transaction body.
    ///
    /// Opening checks that limit and the payload layout before enforcing suite and recipient
    /// agreement, then derives the operation key and authenticates the ciphertext without
    /// changing the envelope.
    ///
    /// Plaintext remains in zeroizing storage on success, while note decoding, commitment
    /// agreement, active protocol rules and transaction authorization and finality remain
    /// consumer checks.
    ///
    /// # Errors
    ///
    /// Payload and algorithm length failures are reported before decapsulation, and framing
    /// errors propagate without returning plaintext.
    ///
    /// Suite or recipient mismatch and failed authentication share
    /// [`NoteDecryptionError::AuthenticationFailed`], without exposing an ML-KEM rejection flag.
    pub fn open(
        &self,
        envelope: &EncryptedNoteEnvelope,
        key: &MlKem1024DecapsulationKey,
        max_payload_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, NoteDecryptionError> {
        let payload = envelope.payload();
        let suite = CryptoSuite::from_note_payload(payload, max_payload_bytes)?;
        if suite != self.suite() {
            return Err(NoteDecryptionError::AuthenticationFailed);
        }

        match suite {
            CryptoSuite::V1 => {
                let plaintext_length = payload.len() - 32;
                sealed_length(plaintext_length, 0, plaintext_length)
                    .map_err(|_| NoteDecryptionError::LengthLimitExceeded)?;
                if &key.encapsulation_key() != self.recipient_key() {
                    return Err(NoteDecryptionError::AuthenticationFailed);
                }

                let nonce: &[u8; 12] = payload[4..16]
                    .try_into()
                    .expect("V1 layout validation guarantees the complete nonce");
                let secret = key.decapsulate(envelope.encapsulation());
                let material = derive_note_material(self, secret, envelope.encapsulation(), nonce)?;
                material
                    .open(&payload[16..], plaintext_length)
                    .map_err(|_| NoteDecryptionError::AuthenticationFailed)
            }
        }
    }
}

/// Public envelope recovery, malformed payload rejection and authenticated input binding.
#[cfg(test)]
mod tests {
    use houseki_types::{
        Amount, CheckpointSequence, EncodedMlDsa87PublicKey, EncodedMlKem1024Ciphertext,
        EncryptedNoteEnvelope, FeeScheduleId, NetworkId, NoteCommitment, NoteRoot, Nullifier,
        PaymentCountLimits, PaymentInputs, ProofProfileId, ProtocolVersion, RewardAccountId,
        TransactionContext, ValidityCheckpointRange, WithdrawalNonce,
    };
    use zeroize::Zeroizing;

    use crate::{
        CryptoSuite, CryptoSuiteError, MlKem1024DecapsulationKey, NoteDecryptionError,
        NoteEncryptionContext, NotePayloadError, PaymentEncryptionCore,
        RewardWithdrawalEncryptionCore,
    };

    /// Builds the declared transaction context with a selectable network.
    fn transaction_context(network: u8) -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([network; 64]),
            ProtocolVersion::new(2),
            ProofProfileId::new(3),
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        )
    }

    /// Prepares either duplicate output to distinguish index binding from commitment binding.
    fn payment(key: &MlKem1024DecapsulationKey, network: u8, index: u64) -> NoteEncryptionContext {
        let limits = PaymentCountLimits::new(1, 2).unwrap();
        let core = PaymentEncryptionCore::new(
            transaction_context(network),
            PaymentInputs::new(
                NoteRoot::from_bytes([9; 64]),
                vec![Nullifier::from_bytes([10; 64])],
                limits,
            )
            .unwrap(),
            vec![(NoteCommitment::from_bytes([11; 64]), CryptoSuite::V1); 2],
            Amount::from_atoms(12).unwrap(),
            limits,
        )
        .unwrap();
        NoteEncryptionContext::for_payment(&core, index, &key.encapsulation_key()).unwrap()
    }

    /// Prepares the withdrawal fixture for the same recipient as the payment fixture.
    fn withdrawal(key: &MlKem1024DecapsulationKey) -> NoteEncryptionContext {
        let core = RewardWithdrawalEncryptionCore::new(
            transaction_context(1),
            RewardAccountId::from_bytes([9; 64]),
            EncodedMlDsa87PublicKey::from_bytes([10; 2592]),
            WithdrawalNonce::new(11),
            Amount::from_atoms(12).unwrap(),
            Amount::from_atoms(13).unwrap(),
            (NoteCommitment::from_bytes([14; 64]), CryptoSuite::V1),
        )
        .unwrap();
        NoteEncryptionContext::for_reward_withdrawal(&core, &key.encapsulation_key()).unwrap()
    }

    /// Stores arbitrary payload bytes without interpreting their suite layout.
    fn envelope(payload: Vec<u8>) -> EncryptedNoteEnvelope {
        EncryptedNoteEnvelope::new(
            EncodedMlKem1024Ciphertext::from_bytes([0; 1568]),
            payload,
            usize::MAX,
        )
        .unwrap()
    }

    /// Checks public recovery into guarded storage without imposing a note plaintext format.
    #[test]
    fn opens_payment_and_withdrawal_envelopes_at_inclusive_limits() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        for context in [payment(&key, 1, 0), withdrawal(&key)] {
            for plaintext in [b"".as_slice(), b"not a canonical note", &[0xa5; 32]] {
                let sealed = context.seal(plaintext, plaintext.len() + 32).unwrap();
                let original = sealed.clone();
                let opened: Zeroizing<Vec<u8>> =
                    context.open(&sealed, &key, sealed.payload_len()).unwrap();
                assert_eq!(opened.as_slice(), plaintext);
                assert_eq!(sealed, original);
            }
        }
    }

    /// Checks the active byte limit before either payload interpretation or recipient matching.
    #[test]
    fn active_payload_limits_are_rechecked_before_recovery() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let wrong_key = MlKem1024DecapsulationKey::from_seed(&[8; 64]);
        let context = payment(&key, 1, 0);
        let sealed = context.seal(b"note", 36).unwrap();
        for candidate in [sealed.clone(), envelope(vec![0xff; 36])] {
            assert!(matches!(
                context.open(&candidate, &wrong_key, 35),
                Err(NoteDecryptionError::Payload(
                    NotePayloadError::PayloadLengthExceedsLimit {
                        actual: 36,
                        maximum: 35,
                    }
                ))
            ));
        }
        assert_eq!(
            context.open(&sealed, &key, usize::MAX).unwrap().as_slice(),
            b"note"
        );
    }

    /// Checks every incomplete V1 layout and preserves unsupported identifiers without fallback.
    #[test]
    fn malformed_payloads_fail_before_recipient_checks() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let wrong_key = MlKem1024DecapsulationKey::from_seed(&[8; 64]);
        let context = payment(&key, 1, 0);
        let sealed = context.seal(b"note", 36).unwrap();
        for length in 0..32 {
            let candidate = envelope(sealed.payload()[..length].to_vec());
            assert!(matches!(
                context.open(&candidate, &wrong_key, length),
                Err(NoteDecryptionError::Payload(NotePayloadError::TruncatedPayload {
                    actual, minimum,
                })) if actual == length && minimum == if length < 4 { 4 } else { 32 }
            ));
        }
        for id in [0_u32, 2, 257, 65_537, u32::MAX] {
            let candidate = envelope(id.to_le_bytes().to_vec());
            assert!(matches!(
                context.open(&candidate, &wrong_key, 4),
                Err(NoteDecryptionError::Payload(NotePayloadError::UnsupportedSuite(
                    CryptoSuiteError::Unsupported { id: actual },
                ))) if actual.value() == id
            ));
        }
    }

    /// Checks recipient, network, core kind and duplicate output index binding.
    #[test]
    fn mismatched_keys_and_contexts_share_authentication_failure() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let wrong_key = MlKem1024DecapsulationKey::from_seed(&[8; 64]);
        let context = payment(&key, 1, 0);
        let sealed = context.seal(b"note", 36).unwrap();
        assert!(matches!(
            context.open(&sealed, &wrong_key, 36),
            Err(NoteDecryptionError::AuthenticationFailed)
        ));
        let wrong_recipient = payment(&wrong_key, 1, 0);
        for supplied_key in [&key, &wrong_key] {
            assert!(matches!(
                wrong_recipient.open(&sealed, supplied_key, 36),
                Err(NoteDecryptionError::AuthenticationFailed)
            ));
        }
        for changed in [payment(&key, 2, 0), payment(&key, 1, 1), withdrawal(&key)] {
            assert!(matches!(
                changed.open(&sealed, &key, 36),
                Err(NoteDecryptionError::AuthenticationFailed)
            ));
        }
    }

    /// Checks all nonce, ciphertext and tag bytes together with encapsulation boundary changes.
    #[test]
    fn altered_envelope_bytes_release_no_plaintext() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let context = payment(&key, 1, 0);
        let sealed = context.seal(b"note", 36).unwrap();
        for index in 4..sealed.payload_len() {
            let mut bytes = sealed.payload().to_vec();
            bytes[index] ^= 1;
            let changed =
                EncryptedNoteEnvelope::new(sealed.encapsulation().clone(), bytes, 36).unwrap();
            let original = changed.clone();
            assert!(matches!(
                context.open(&changed, &key, 36),
                Err(NoteDecryptionError::AuthenticationFailed)
            ));
            assert_eq!(changed, original);
        }
        for index in [0, 783, 1567] {
            let mut bytes = *sealed.encapsulation().as_bytes();
            bytes[index] ^= 1;
            let changed = EncryptedNoteEnvelope::new(
                EncodedMlKem1024Ciphertext::from_bytes(bytes),
                sealed.payload().to_vec(),
                36,
            )
            .unwrap();
            assert!(matches!(
                context.open(&changed, &key, 36),
                Err(NoteDecryptionError::AuthenticationFailed)
            ));
        }
    }

    /// Checks that a structurally complete truncation or extension still requires authentication.
    #[test]
    fn complete_but_resized_payloads_fail_authentication() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let context = payment(&key, 1, 0);
        let sealed = context.seal(b"note", 36).unwrap();
        for length in 32..sealed.payload_len() {
            let changed = EncryptedNoteEnvelope::new(
                sealed.encapsulation().clone(),
                sealed.payload()[..length].to_vec(),
                36,
            )
            .unwrap();
            assert!(matches!(
                context.open(&changed, &key, 36),
                Err(NoteDecryptionError::AuthenticationFailed)
            ));
        }
        let mut payload = sealed.payload().to_vec();
        payload.push(0);
        let changed =
            EncryptedNoteEnvelope::new(sealed.encapsulation().clone(), payload, 37).unwrap();
        assert!(matches!(
            context.open(&changed, &key, 37),
            Err(NoteDecryptionError::AuthenticationFailed)
        ));
    }
}
