//! Fresh encapsulation and authenticated payload encoding for complete note envelopes.

mod error;

pub use error::NoteEncryptionError;

use super::{
    CryptoSuite, NoteEncryptionContext, aead::sealed_length, key_derivation::derive_note_material,
};
use crate::random::secret_bytes;
use getrandom::{SysRng, rand_core::TryCryptoRng};
use houseki_types::{EncryptedNoteEnvelope, EncryptedNoteEnvelopeError};

impl NoteEncryptionContext {
    /// Encrypts padded note bytes into a fresh envelope for this output and recipient.
    ///
    /// Each call obtains a fresh nonce and ML-KEM encapsulation from the system random source,
    /// then derives the operation key from this context and seals the supplied bytes.
    ///
    /// The V1 payload contains the four byte little endian suite identifier, 12 byte nonce and
    /// ciphertext with its 16 byte tag, while the envelope carries the encapsulation separately.
    ///
    /// The inclusive `max_payload_bytes` limit covers that complete payload, so it must allow
    /// 32 bytes beyond the plaintext length and does not include the encapsulation or body.
    ///
    /// The caller supplies canonical padded note bytes and retains responsibility for clearing
    /// their borrowed storage, checking active suite rules and note and recipient validity,
    /// and binding the completed envelope into the final transaction body.
    ///
    /// # Errors
    ///
    /// Payload, algorithm and host length failures are rejected before obtaining randomness
    /// or copying plaintext, with no envelope returned after an entropy, framing or encryption
    /// failure.
    pub fn seal(
        &self,
        plaintext: &[u8],
        max_payload_bytes: usize,
    ) -> Result<EncryptedNoteEnvelope, NoteEncryptionError> {
        self.seal_with_rng(plaintext, max_payload_bytes, &mut SysRng)
    }

    /// Seals with an internal entropy source after checking the complete payload length.
    ///
    /// Nonce acquisition precedes encapsulation so all entropy failures occur before key
    /// derivation, while the public operation always supplies the system source.
    fn seal_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        plaintext: &[u8],
        max_payload_bytes: usize,
        rng: &mut R,
    ) -> Result<EncryptedNoteEnvelope, NoteEncryptionError> {
        match self.suite() {
            CryptoSuite::V1 => {
                let length = payload_length(plaintext.len(), max_payload_bytes)?;

                let nonce = secret_bytes::<12, _>(rng)
                    .map_err(|_| NoteEncryptionError::RandomnessUnavailable)?;
                let (encapsulation, secret) = self
                    .recipient_key()
                    .encapsulate_with_rng(rng)
                    .map_err(|_| NoteEncryptionError::RandomnessUnavailable)?;

                let material = derive_note_material(self, secret, &encapsulation, &nonce)?;
                let ciphertext = material
                    .seal(plaintext, plaintext.len())
                    .map_err(|_| NoteEncryptionError::EncryptionFailed)?;

                let mut payload = Vec::with_capacity(length);
                payload.extend_from_slice(&self.suite().id().value().to_le_bytes());
                payload.extend_from_slice(&*nonce);
                payload.extend_from_slice(&ciphertext);

                EncryptedNoteEnvelope::new(encapsulation, payload, max_payload_bytes).map_err(
                    |error| match error {
                        EncryptedNoteEnvelopeError::PayloadLengthExceedsLimit {
                            actual,
                            maximum,
                        } => NoteEncryptionError::PayloadLengthExceedsLimit { actual, maximum },
                    },
                )
            }
        }
    }
}

/// Checks the complete V1 payload length before entropy acquisition or plaintext allocation.
///
/// The shared AEAD check applies its plaintext ceiling here and checks actual associated data
/// again during encryption, while the final host bound also includes the header and nonce.
fn payload_length(plaintext: usize, maximum: usize) -> Result<usize, NoteEncryptionError> {
    let length = plaintext
        .checked_add(32)
        .ok_or(NoteEncryptionError::LengthLimitExceeded)?;
    if length > maximum {
        return Err(NoteEncryptionError::PayloadLengthExceedsLimit {
            actual: length,
            maximum,
        });
    }

    sealed_length(plaintext, 0, plaintext).map_err(|_| NoteEncryptionError::LengthLimitExceeded)?;
    isize::try_from(length).map_err(|_| NoteEncryptionError::LengthLimitExceeded)?;

    Ok(length)
}

/// Envelope layout, entropy failures, message bounds and authenticated recovery.
#[cfg(test)]
mod tests {
    use super::payload_length;
    use crate::{
        CryptoSuite, MlKem1024DecapsulationKey, NoteEncryptionContext, NoteEncryptionError,
        PaymentEncryptionCore, RewardWithdrawalEncryptionCore,
        suite::key_derivation::derive_note_material,
    };
    use getrandom::rand_core::{TryCryptoRng, TryRng};
    use houseki_types::{
        Amount, CheckpointSequence, EncodedMlDsa87PublicKey, EncryptedNoteEnvelope, FeeScheduleId,
        NetworkId, NoteCommitment, NoteRoot, Nullifier, PaymentCountLimits, PaymentInputs,
        ProofProfileId, ProtocolVersion, RewardAccountId, TransactionContext,
        ValidityCheckpointRange, WithdrawalNonce,
    };

    /// Builds the transaction context shared by payment and withdrawal fixtures.
    fn transaction_context() -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes([1; 64]),
            ProtocolVersion::new(2),
            ProofProfileId::new(3),
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        )
    }

    /// Prepares a payment output for the supplied private key's recipient.
    fn payment(key: &MlKem1024DecapsulationKey) -> NoteEncryptionContext {
        let limits = PaymentCountLimits::new(1, 1).unwrap();
        let core = PaymentEncryptionCore::new(
            transaction_context(),
            PaymentInputs::new(
                NoteRoot::from_bytes([9; 64]),
                vec![Nullifier::from_bytes([10; 64])],
                limits,
            )
            .unwrap(),
            vec![(NoteCommitment::from_bytes([11; 64]), CryptoSuite::V1)],
            Amount::from_atoms(12).unwrap(),
            limits,
        )
        .unwrap();

        NoteEncryptionContext::for_payment(&core, 0, &key.encapsulation_key()).unwrap()
    }

    /// Prepares a withdrawal output with the same recipient as the payment fixture.
    fn withdrawal(key: &MlKem1024DecapsulationKey) -> NoteEncryptionContext {
        let core = RewardWithdrawalEncryptionCore::new(
            transaction_context(),
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

    /// Recovers through existing primitives after independently splitting the wire fields.
    fn recover(
        context: &NoteEncryptionContext,
        key: &MlKem1024DecapsulationKey,
        envelope: &EncryptedNoteEnvelope,
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let payload = envelope.payload();
        assert_eq!(&payload[..4], &1_u32.to_le_bytes());

        let nonce: &[u8; 12] = payload[4..16].try_into().unwrap();
        let secret = key.decapsulate(envelope.encapsulation());

        derive_note_material(context, secret, envelope.encapsulation(), nonce)
            .unwrap()
            .open(&payload[16..], payload.len() - 32)
            .ok()
    }

    /// Checks exact wire boundaries and recovery for both core kinds and empty plaintext.
    #[test]
    fn sealing_produces_complete_recoverable_envelopes_at_the_exact_limit() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        for context in [payment(&key), withdrawal(&key)] {
            for plaintext in [b"".as_slice(), b"note", &[0xa5; 32]] {
                let original = plaintext.to_vec();
                let mut rng = FixtureRng::default();

                let envelope = context
                    .seal_with_rng(plaintext, plaintext.len() + 32, &mut rng)
                    .unwrap();

                assert_eq!(rng.position, 44);
                assert_eq!(envelope.payload_len(), plaintext.len() + 32);
                assert_eq!(
                    &envelope.payload()[4..16],
                    &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
                );
                assert_eq!(
                    CryptoSuite::from_note_payload(envelope.payload(), envelope.payload_len())
                        .unwrap(),
                    context.suite()
                );
                assert_eq!(
                    recover(&context, &key, &envelope).unwrap().as_slice(),
                    plaintext
                );
                assert_eq!(plaintext, original);
            }
        }
    }

    /// Checks that undersized limits fail before either source of operation randomness is used.
    #[test]
    fn excessive_payload_lengths_do_not_consume_entropy() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let context = payment(&key);

        for (plaintext, maximum) in [(b"".as_slice(), 0), (b"", 31), (b"note", 35)] {
            let mut rng = FixtureRng::default();

            assert!(matches!(
                context.seal_with_rng(plaintext, maximum, &mut rng),
                Err(NoteEncryptionError::PayloadLengthExceedsLimit { actual, maximum: limit })
                    if actual == plaintext.len() + 32 && limit == maximum
            ));
            assert_eq!(rng.position, 0);
        }
    }

    /// Checks every partial failure while acquiring the nonce and KEM randomness.
    #[test]
    fn entropy_failure_never_returns_a_partial_envelope() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let context = payment(&key);

        for fail_after in 0..44 {
            let mut rng = FixtureRng {
                position: 0,
                fail_after: Some(fail_after),
            };

            assert!(matches!(
                context.seal_with_rng(b"note", 36, &mut rng),
                Err(NoteEncryptionError::RandomnessUnavailable)
            ));
            assert_eq!(rng.position, fail_after);
        }
    }

    /// Checks arithmetic and algorithm limits without allocating synthetic message lengths.
    #[test]
    fn payload_bounds_include_the_header_nonce_and_tag() {
        assert_eq!(payload_length(0, 32).unwrap(), 32);
        assert_eq!(payload_length(16, 48).unwrap(), 48);

        for length in [usize::MAX, isize::MAX as usize] {
            assert!(matches!(
                payload_length(length, usize::MAX),
                Err(NoteEncryptionError::LengthLimitExceeded)
            ));
        }

        if let Ok(maximum) = usize::try_from(aes_gcm_siv::P_MAX) {
            assert_eq!(payload_length(maximum, usize::MAX).unwrap(), maximum + 32);
            assert!(matches!(
                payload_length(maximum + 1, usize::MAX),
                Err(NoteEncryptionError::LengthLimitExceeded)
            ));
        }
    }

    /// Checks that the public operation obtains fresh encapsulation and nonce bytes each time.
    #[test]
    fn public_sealing_uses_fresh_operation_randomness() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let context = payment(&key);

        let first = context.seal(b"note", 36).unwrap();
        let second = context.seal(b"note", 36).unwrap();

        assert_ne!(first.encapsulation(), second.encapsulation());
        assert_ne!(&first.payload()[4..16], &second.payload()[4..16]);

        for envelope in [first, second] {
            assert_eq!(
                recover(&context, &key, &envelope).unwrap().as_slice(),
                b"note"
            );
        }
    }

    /// Checks that published envelope bytes remain bound to their context and recipient key.
    #[test]
    fn altered_envelopes_and_recipients_fail_authentication() {
        let key = MlKem1024DecapsulationKey::from_seed(&[7; 64]);
        let wrong_key = MlKem1024DecapsulationKey::from_seed(&[8; 64]);
        let context = payment(&key);

        let envelope = context
            .seal_with_rng(b"note", 36, &mut FixtureRng::default())
            .unwrap();

        assert!(recover(&context, &wrong_key, &envelope).is_none());
        assert!(recover(&withdrawal(&key), &key, &envelope).is_none());

        for index in 4..envelope.payload_len() {
            let mut bytes = envelope.payload().to_vec();
            bytes[index] ^= 1;

            let changed =
                EncryptedNoteEnvelope::new(envelope.encapsulation().clone(), bytes, 36).unwrap();

            assert!(recover(&context, &key, &changed).is_none());
        }

        let mut bytes = *envelope.encapsulation().as_bytes();
        bytes[0] ^= 1;

        let changed = EncryptedNoteEnvelope::new(
            houseki_types::EncodedMlKem1024Ciphertext::from_bytes(bytes),
            envelope.payload().to_vec(),
            36,
        )
        .unwrap();

        assert!(recover(&context, &key, &changed).is_none());
    }

    /// Predictable entropy stream with an optional failure after a partial write.
    #[derive(Default)]
    struct FixtureRng {
        /// Number of bytes successfully written across requests.
        position: usize,

        /// Stream position at which entropy acquisition fails.
        fail_after: Option<usize>,
    }

    // This predictable source is confined to tests and cannot be supplied to the public API.
    impl TryCryptoRng for FixtureRng {}

    impl TryRng for FixtureRng {
        /// Synthetic error used to exercise partial entropy failures.
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

        /// Writes consecutive fixture bytes until the configured failure position.
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for byte in output {
                if self.fail_after == Some(self.position) {
                    return Err(std::io::Error::other("fixture entropy exhausted"));
                }

                *byte = u8::try_from(self.position % 256).unwrap();
                self.position += 1;
            }

            Ok(())
        }
    }
}
