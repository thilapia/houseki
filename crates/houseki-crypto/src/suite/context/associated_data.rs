//! Canonical associated data derived from a prepared output context.

use houseki_types::EncodedMlKem1024Ciphertext;

use super::NoteEncryptionContext;
use crate::{
    CryptoFramingError, CryptoSuite,
    domain::{Domain, Frame},
};

impl NoteEncryptionContext {
    /// Builds the canonical associated data for this output and operation.
    ///
    /// The `houseki/v1/note/aad` frame starts with the network, protocol version and suite,
    /// followed by the core digest, output index and commitment.
    ///
    /// It then binds the recipient key through an internally derived hash before including the
    /// complete KEM ciphertext and nonce.
    ///
    /// Version and suite occupy four little endian bytes and the index eight, while the
    /// network, digests and commitment each occupy 64 bytes.
    ///
    /// Together with framing and the 12 byte nonce, these fields produce 1949 bytes for V1.
    ///
    /// The stable recipient binding makes this local KDF and AEAD input, which recovery
    /// reconstructs instead of publishing in the envelope.
    ///
    /// Sealing supplies fresh encapsulation and nonce values and recovery supplies their
    /// transmitted values, but framing itself neither checks freshness nor authenticates
    /// ciphertext.
    ///
    /// # Errors
    ///
    /// Propagates [`CryptoFramingError`] from recipient binding or framing without returning
    /// partial output.
    pub fn associated_data(
        &self,
        encapsulation: &EncodedMlKem1024Ciphertext,
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, CryptoFramingError> {
        match self.suite() {
            CryptoSuite::V1 => {
                let context = self.transaction_context();
                let binding = self
                    .suite()
                    .recipient_key_binding(context.network_id(), self.recipient_key())?;

                // 25 header bytes, nine 8 byte lengths, 1852 field bytes.
                let mut bytes = Vec::with_capacity(1949);
                let mut sink = |chunk: &[u8]| bytes.extend_from_slice(chunk);
                let mut frame = Frame::new(Domain::NoteAssociatedData, 9, &mut sink);
                frame.part(context.network_id().as_bytes())?;
                frame.part(&context.protocol_version().value().to_le_bytes())?;
                frame.part(&self.suite().id().value().to_le_bytes())?;
                frame.part(self.core_digest())?;
                frame.part(&self.output_index().to_le_bytes())?;
                frame.part(self.note_commitment().as_bytes())?;
                frame.part(&binding)?;
                frame.part(encapsulation.as_bytes())?;
                frame.part(nonce)?;
                frame.finish()?;

                Ok(bytes)
            }
        }
    }
}

/// Exact associated data layouts and complete input binding.
#[cfg(test)]
mod tests {
    use houseki_types::{
        Amount, CheckpointSequence, EncodedMlDsa87PublicKey, EncodedMlKem1024PublicKey,
        FeeScheduleId, NetworkId, NoteCommitment, NoteRoot, Nullifier, PaymentCountLimits,
        PaymentInputs, ProofProfileId, ProtocolVersion, RewardAccountId, TransactionContext,
        ValidityCheckpointRange, WithdrawalNonce,
    };

    use super::{EncodedMlKem1024Ciphertext, NoteEncryptionContext};
    use crate::{
        CryptoSuite, MlKem1024EncapsulationKey, PaymentEncryptionCore,
        RewardWithdrawalEncryptionCore,
    };

    /// Constructs a canonical public key fixture with the supplied matrix seed.
    fn key(seed: u8) -> MlKem1024EncapsulationKey {
        let mut bytes = [0; 1568];
        bytes[1536..].fill(seed);

        MlKem1024EncapsulationKey::try_from(&EncodedMlKem1024PublicKey::from_bytes(bytes)).unwrap()
    }

    /// Builds a declared context fixture for this module's binding checks.
    fn context() -> TransactionContext {
        TransactionContext::new(
            NetworkId::from_bytes(std::array::from_fn(|i| u8::try_from(i).unwrap())),
            ProtocolVersion::new(0x01020304),
            ProofProfileId::new(3),
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        )
    }

    /// Builds the payment fixture used by this module's codec checks.
    fn payment() -> PaymentEncryptionCore {
        let limits = PaymentCountLimits::new(2, 3).unwrap();
        PaymentEncryptionCore::new(
            context(),
            PaymentInputs::new(
                NoteRoot::from_bytes([9; 64]),
                [10, 11].map(|x| Nullifier::from_bytes([x; 64])).to_vec(),
                limits,
            )
            .unwrap(),
            [12, 13, 12]
                .map(|x| (NoteCommitment::from_bytes([x; 64]), CryptoSuite::V1))
                .to_vec(),
            Amount::from_atoms(17).unwrap(),
            limits,
        )
        .unwrap()
    }

    /// Builds the withdrawal fixture used by this module's codec checks.
    fn withdrawal() -> RewardWithdrawalEncryptionCore {
        RewardWithdrawalEncryptionCore::new(
            context(),
            RewardAccountId::from_bytes([14; 64]),
            EncodedMlDsa87PublicKey::from_bytes([15; 2592]),
            WithdrawalNonce::new(16),
            Amount::from_atoms(17).unwrap(),
            Amount::from_atoms(18).unwrap(),
            (NoteCommitment::from_bytes([19; 64]), CryptoSuite::V1),
        )
        .unwrap()
    }

    // Independent decoding checks the exact label, count, field lengths, ordering and absence
    // of trailing data without using the Frame encoder.
    /// Decodes and checks the exact associated data layout independently of its encoder.
    fn parts(bytes: &[u8]) -> Vec<&[u8]> {
        assert_eq!(&bytes[..25], b"\x13\x00houseki/v1/note/aad\x09\x00\x00\x00");

        let mut rest = &bytes[25..];
        let mut fields = Vec::new();
        for expected_length in [64, 4, 4, 64, 8, 64, 64, 1568, 12] {
            let (length, tail) = rest.split_at(8);
            assert_eq!(
                u64::from_le_bytes(length.try_into().unwrap()),
                expected_length
            );

            let (field, tail) = tail.split_at(usize::try_from(expected_length).unwrap());
            fields.push(field);
            rest = tail;
        }

        assert!(rest.is_empty());

        fields
    }

    /// Formats public fixture bytes as lowercase hexadecimal.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Checks every associated data field for both transaction kinds.
    #[test]
    fn complete_payment_and_withdrawal_transcripts_match_the_specified_codec() {
        let key = key(0);
        let encapsulation = EncodedMlKem1024Ciphertext::from_bytes(std::array::from_fn(|i| {
            u8::try_from(i % 256).unwrap()
        }));
        let nonce = std::array::from_fn(|i| u8::try_from(i + 128).unwrap());

        // Core hashes independently computed with Python hashlib.sha3_512 and the documented
        // core codec.
        // E is the independent Poseidon2 vector already pinned by the recipient binding
        // operation.
        for (prepared, index, commitment, digest) in [
            (
                NoteEncryptionContext::for_payment(&payment(), 2, &key).unwrap(),
                2_u64,
                12,
                "1f91e67ef8fe4b0b8210a0ea1c1d48cac1ea944a957caebd1c68ee9f9ab673f8332abf67bb6a7c4cf063d925b7468e04512855800bac1e937783901ea30b6bbc",
            ),
            (
                NoteEncryptionContext::for_reward_withdrawal(&withdrawal(), &key).unwrap(),
                0,
                19,
                "c9e3202e5f5e59c7facecb3f21d5d4e60faecdf478e6283c6a33d1b700a64be2c4686eeaca97535c7cdc530d473a874d9048541ff4cb989e180bae928cca22c2",
            ),
        ] {
            let encoded = prepared.associated_data(&encapsulation, &nonce).unwrap();

            assert_eq!(encoded.len(), 1949);

            let fields = parts(&encoded);

            assert_eq!(fields[0], context().network_id().as_bytes());
            assert_eq!(fields[1], [4, 3, 2, 1]);
            assert_eq!(fields[2], [1, 0, 0, 0]);
            assert_eq!(hex(fields[3]), digest);
            assert_eq!(fields[4], index.to_le_bytes());
            assert_eq!(fields[5], [commitment; 64]);
            assert_eq!(
                hex(fields[6]),
                "f001ec9a7577a1366a3f0742913a65fa1530446a8df7c9db52896d0459b514acfdbe01363ce585fb1473cf32a9ba8602a235e57a0f5f016f95d7c157590a7b7c"
            );
            assert_eq!(fields[7], encapsulation.as_bytes());
            assert_eq!(fields[8], nonce);
        }
    }

    /// Checks that output position and recipient changes alter their framed fields.
    #[test]
    fn duplicate_output_positions_and_recipient_keys_have_distinct_transcripts() {
        let core = payment();
        let encapsulation = EncodedMlKem1024Ciphertext::from_bytes([0; 1568]);
        let first = NoteEncryptionContext::for_payment(&core, 0, &key(0)).unwrap();
        let original = first.associated_data(&encapsulation, &[0; 12]).unwrap();

        for (index, seed, changed_field) in [(2, 0, 4), (0, 255, 6)] {
            let changed = NoteEncryptionContext::for_payment(&core, index, &key(seed))
                .unwrap()
                .associated_data(&encapsulation, &[0; 12])
                .unwrap();

            for (i, (a, b)) in parts(&original).iter().zip(parts(&changed)).enumerate() {
                if i == changed_field {
                    assert_ne!(*a, b);
                } else {
                    assert_eq!(*a, b);
                }
            }
        }
    }

    /// Checks that an unselected output remains bound by the core digest.
    #[test]
    fn changes_outside_the_selected_output_are_bound_through_the_core_digest() {
        let core = payment();
        let original = NoteEncryptionContext::for_payment(&core, 0, &key(0)).unwrap();

        let (context, inputs, mut outputs, fee) = core.into_parts();
        outputs[1].0 = NoteCommitment::from_bytes([99; 64]);
        let changed_core = PaymentEncryptionCore::new(
            context,
            inputs,
            outputs,
            fee,
            PaymentCountLimits::new(2, 3).unwrap(),
        )
        .unwrap();
        let changed = NoteEncryptionContext::for_payment(&changed_core, 0, &key(0)).unwrap();

        let encapsulation = EncodedMlKem1024Ciphertext::from_bytes([0; 1568]);
        let a = original.associated_data(&encapsulation, &[0; 12]).unwrap();
        let b = changed.associated_data(&encapsulation, &[0; 12]).unwrap();

        for (i, (a, b)) in parts(&a).iter().zip(parts(&b)).enumerate() {
            if i == 3 {
                assert_ne!(*a, b);
            } else {
                assert_eq!(*a, b);
            }
        }
    }

    /// Checks complete operation byte preservation and recovery reconstruction.
    #[test]
    fn encapsulation_and_nonce_bytes_are_preserved_without_interpretation() {
        let prepared = NoteEncryptionContext::for_payment(&payment(), 0, &key(0)).unwrap();
        for byte in [0, 255] {
            let encapsulation = EncodedMlKem1024Ciphertext::from_bytes([byte; 1568]);
            let nonce = [byte; 12];
            let a = prepared.associated_data(&encapsulation, &nonce).unwrap();

            assert_eq!(parts(&a)[7], [byte; 1568]);
            assert_eq!(parts(&a)[8], [byte; 12]);

            let recovered = NoteEncryptionContext::for_payment(&payment(), 0, &key(0)).unwrap();

            assert_eq!(
                a,
                recovered.associated_data(&encapsulation, &nonce).unwrap()
            );
        }
    }

    /// Checks all output index bytes at the private codec boundary.
    #[test]
    fn output_index_encoding_preserves_all_eight_bytes() {
        let mut prepared = NoteEncryptionContext::for_payment(&payment(), 0, &key(0)).unwrap();
        // Exercise the private codec boundary without allocating an enormous output list.
        // Public construction still rejects absent indices.
        prepared.output_index = 0x0102030405060708;

        let encoded = prepared
            .associated_data(&EncodedMlKem1024Ciphertext::from_bytes([0; 1568]), &[0; 12])
            .unwrap();

        assert_eq!(parts(&encoded)[4], [8, 7, 6, 5, 4, 3, 2, 1]);
    }
}
