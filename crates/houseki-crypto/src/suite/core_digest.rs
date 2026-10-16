use houseki_types::TransactionContext;

use crate::{
    CryptoFramingError,
    domain::{Domain, Frame},
    hash::sha3_512,
};

use super::{PaymentEncryptionCore, RewardWithdrawalEncryptionCore};

impl PaymentEncryptionCore {
    /// Derives the 64 byte SHA3-512 digest of the complete encryption core.
    ///
    /// The fixed `houseki/v1/note/encryption-core` frame binds a `payment`
    /// tag, the complete context, anchor, actual input count, ordered nullifiers,
    /// public fee, actual output count and ordered commitment/suite pairs.
    /// Integers use fixed width little endian encodings. Hashing streams the
    /// fields without allocating a second copy of the core.
    ///
    /// Version and suite identifiers use four bytes, checkpoints and list
    /// counts eight, and the fee sixteen. Byte identifiers use all 64 bytes.
    /// Every field is a separate length-prefixed part, including each
    /// commitment and its suite. The frame has `11 + inputs + 2 * outputs`
    /// parts and requires that total to fit in a `u32`.
    ///
    /// This is neither the transaction ID nor the AIR effect digest. It does
    /// not establish transaction validity or authenticate a completed body.
    /// Future encryption context construction must derive it from this core,
    /// rather than accepting externally supplied digest bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoFramingError`] if the layout exceeds framing limits or
    /// the encoder's emitted part count does not match its declaration.
    pub fn digest(&self) -> Result<[u8; 64], CryptoFramingError> {
        let input_count = self.inputs().input_count();
        let output_count = self.outputs().len();
        let part_count = payment_part_count(input_count, output_count)?;
        let input_count =
            u64::try_from(input_count).map_err(|_| CryptoFramingError::TooManyParts)?;
        let output_count =
            u64::try_from(output_count).map_err(|_| CryptoFramingError::TooManyParts)?;

        sha3_512(|sink| {
            let mut frame = Frame::new(Domain::NoteEncryptionCore, part_count, sink);
            frame_context(&mut frame, b"payment", self.context())?;
            frame.part(self.inputs().anchor().as_bytes())?;
            frame.part(&input_count.to_le_bytes())?;
            for nullifier in self.inputs().nullifiers() {
                frame.part(nullifier.as_bytes())?;
            }
            frame.part(&self.public_fee().atoms().to_le_bytes())?;
            frame.part(&output_count.to_le_bytes())?;
            for (commitment, suite) in self.outputs() {
                frame.part(commitment.as_bytes())?;
                frame.part(&suite.id().value().to_le_bytes())?;
            }
            frame.finish()
        })
    }
}

impl RewardWithdrawalEncryptionCore {
    /// Derives the 64 byte SHA3-512 digest of the complete encryption core.
    ///
    /// The fixed `houseki/v1/note/encryption-core` frame binds a
    /// `reward-withdrawal` tag, complete context, account identifier, encoded
    /// authority key, nonce, public amount, fee, single output count and
    /// commitment/suite pair. Integers use fixed width little endian encodings.
    /// Hashing streams the fields without allocating a second copy of the core.
    ///
    /// Version and suite identifiers use four bytes, checkpoints, nonce and
    /// the output count eight, and amount and fee sixteen. Byte identifiers
    /// use all 64 bytes and the authority key uses all 2592 encoded bytes.
    /// Every field is a separate length-prefixed part, including the output
    /// commitment and its suite.
    ///
    /// This is neither the transaction ID nor the AIR effect digest. It does
    /// not validate the declared key, account binding or withdrawal authority.
    /// Future encryption context construction must derive it from this core,
    /// rather than accepting externally supplied digest bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoFramingError`] if the encoder cannot represent or
    /// complete the declared frame. This layout has 15 fixed width parts.
    pub fn digest(&self) -> Result<[u8; 64], CryptoFramingError> {
        sha3_512(|sink| {
            let mut frame = Frame::new(Domain::NoteEncryptionCore, 15, sink);
            frame_context(&mut frame, b"reward-withdrawal", self.context())?;
            frame.part(self.reward_account_id().as_bytes())?;
            frame.part(self.withdrawal_public_key().as_bytes())?;
            frame.part(&self.nonce().value().to_le_bytes())?;
            frame.part(&self.public_amount().atoms().to_le_bytes())?;
            frame.part(&self.public_fee().atoms().to_le_bytes())?;
            frame.part(&1_u64.to_le_bytes())?;
            let (commitment, suite) = self.output();
            frame.part(commitment.as_bytes())?;
            frame.part(&suite.id().value().to_le_bytes())?;
            frame.finish()
        })
    }
}

fn payment_part_count(inputs: usize, outputs: usize) -> Result<u32, CryptoFramingError> {
    let inputs = u32::try_from(inputs).map_err(|_| CryptoFramingError::TooManyParts)?;
    let outputs = u32::try_from(outputs).map_err(|_| CryptoFramingError::TooManyParts)?;
    // Seven context parts, anchor, input count, fee, output count, plus each
    // nullifier and two separate parts for each commitment/suite pair.
    outputs
        .checked_mul(2)
        .and_then(|parts| parts.checked_add(inputs))
        .and_then(|parts| parts.checked_add(11))
        .ok_or(CryptoFramingError::TooManyParts)
}

fn frame_context(
    frame: &mut Frame<'_>,
    operation: &[u8],
    context: TransactionContext,
) -> Result<(), CryptoFramingError> {
    frame.part(operation)?;
    frame.part(context.network_id().as_bytes())?;
    frame.part(&context.protocol_version().value().to_le_bytes())?;
    frame.part(&context.proof_profile_id().value().to_le_bytes())?;
    frame.part(&context.fee_schedule_id().value().to_le_bytes())?;
    frame.part(
        &context
            .validity_checkpoint_range()
            .start()
            .value()
            .to_le_bytes(),
    )?;
    frame.part(
        &context
            .validity_checkpoint_range()
            .end()
            .value()
            .to_le_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use houseki_types::{
        Amount, CheckpointSequence, EncodedMlDsa87PublicKey, FeeScheduleId, NetworkId,
        NoteCommitment, NoteRoot, Nullifier, PaymentCountLimits, PaymentInputs, ProofProfileId,
        ProtocolVersion, RewardAccountId, TransactionContext, ValidityCheckpointRange,
        WithdrawalNonce,
    };

    use super::{
        CryptoFramingError, PaymentEncryptionCore, RewardWithdrawalEncryptionCore,
        payment_part_count,
    };
    use crate::CryptoSuite;

    fn context(changed_field: Option<usize>) -> TransactionContext {
        let mut network = std::array::from_fn(|index| u8::try_from(index).unwrap());
        let mut protocol = 0x01020304;
        let mut proof = 0x11121314;
        let mut fees = 0x21222324;
        let mut start = 0x0102030405060708;
        let mut end = 0x1112131415161718;
        match changed_field {
            Some(0) => network[63] ^= 1,
            Some(1) => protocol ^= 1 << 24,
            Some(2) => proof ^= 1 << 24,
            Some(3) => fees ^= 1 << 24,
            Some(4) => start ^= 1 << 32,
            Some(5) => end ^= 1 << 32,
            None => {}
            _ => panic!("unknown context field"),
        }
        TransactionContext::new(
            NetworkId::from_bytes(network),
            ProtocolVersion::new(protocol),
            ProofProfileId::new(proof),
            FeeScheduleId::new(fees),
            ValidityCheckpointRange::new(
                CheckpointSequence::new(start),
                CheckpointSequence::new(end),
            )
            .unwrap(),
        )
    }

    fn limits() -> PaymentCountLimits {
        PaymentCountLimits::new(4, 4).unwrap()
    }

    fn fee() -> Amount {
        Amount::from_atoms((1 << 80) + 0x2122232425262728).unwrap()
    }

    fn payment(context: TransactionContext) -> PaymentEncryptionCore {
        PaymentEncryptionCore::new(
            context,
            PaymentInputs::new(
                NoteRoot::from_bytes([0x30; 64]),
                [0x31, 0x32]
                    .map(|byte| Nullifier::from_bytes([byte; 64]))
                    .to_vec(),
                limits(),
            )
            .unwrap(),
            [0x41, 0x42, 0x41]
                .map(|byte| (NoteCommitment::from_bytes([byte; 64]), CryptoSuite::V1))
                .to_vec(),
            fee(),
            limits(),
        )
        .unwrap()
    }

    fn withdrawal(context: TransactionContext) -> RewardWithdrawalEncryptionCore {
        RewardWithdrawalEncryptionCore::new(
            context,
            RewardAccountId::from_bytes([0x51; 64]),
            EncodedMlDsa87PublicKey::from_bytes(std::array::from_fn(|index| {
                u8::try_from(index % 256).unwrap()
            })),
            WithdrawalNonce::new(0x3132333435363738),
            Amount::from_atoms((1 << 88) + 0x4142434445464748).unwrap(),
            fee(),
            (NoteCommitment::from_bytes([0x61; 64]), CryptoSuite::V1),
        )
        .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn core_digests_match_independently_encoded_sha3_512_vectors() {
        // Independently assembled with Python int.to_bytes(n, "little") and
        // hashlib.sha3_512. The label is 31 bytes. Each part gets a u64 length.
        // Payment has 19 parts / 716 framed bytes, withdrawal 15 / 3038.
        // The fixtures pin the operation tags, all integer widths, output
        // multiplicity and suite ID 1. They are Houseki codec vectors, not NIST
        // vectors or evidence of validity of the declared authority key.
        assert_eq!(
            hex(&payment(context(None)).digest().unwrap()),
            concat!(
                "a6055fd648bee211edc834f0c9ad7b589efa077a1bcc09882e4567e567247dc8e",
                "fd22bf4eea164b66af623b65f03d998273e9769fba983eaaa183e4ed718d3db"
            )
        );
        assert_eq!(
            hex(&withdrawal(context(None)).digest().unwrap()),
            concat!(
                "e3cfa4e0f6312fcc47233e175b7fdbec53ec4eb56a9f3331e9c944889caea2813",
                "130003ba022d6cefdaaa5efe6d35bae78d8ce20e1c9bb5e368fe3b9bd5f6167"
            )
        );
    }

    #[test]
    fn every_context_field_is_bound_for_both_operations() {
        let payment_digest = payment(context(None)).digest().unwrap();
        let withdrawal_digest = withdrawal(context(None)).digest().unwrap();
        for field in 0..6 {
            assert_ne!(
                payment(context(Some(field))).digest().unwrap(),
                payment_digest,
                "payment context field {field}"
            );
            assert_ne!(
                withdrawal(context(Some(field))).digest().unwrap(),
                withdrawal_digest,
                "withdrawal context field {field}"
            );
        }
    }

    #[test]
    fn payment_binds_source_fee_output_order_and_multiplicity() {
        let original = payment(context(None));
        let expected = original.digest().unwrap();
        for change in 0..9 {
            let (context, inputs, mut outputs, mut fee) = original.clone().into_parts();
            let mut anchor = inputs.anchor();
            let mut nullifiers = inputs.nullifiers().to_vec();
            match change {
                0 => anchor = NoteRoot::from_bytes([0x33; 64]),
                1 => nullifiers[1] = Nullifier::from_bytes([0x34; 64]),
                2 => {
                    nullifiers.pop();
                }
                3 => nullifiers.swap(0, 1),
                4 => fee = Amount::from_atoms(fee.atoms() + (1 << 64)).unwrap(),
                5 => outputs[1].0 = NoteCommitment::from_bytes([0x43; 64]),
                6 => {
                    outputs.pop();
                }
                7 => outputs.swap(0, 1),
                8 => outputs.push(outputs[0]),
                _ => unreachable!(),
            }
            let changed = PaymentEncryptionCore::new(
                context,
                PaymentInputs::new(anchor, nullifiers, limits()).unwrap(),
                outputs,
                fee,
                limits(),
            )
            .unwrap();
            assert_ne!(
                changed.digest().unwrap(),
                expected,
                "payment change {change}"
            );
        }
    }

    #[test]
    fn withdrawal_binds_account_complete_key_nonce_amount_fee_and_output() {
        let original = withdrawal(context(None));
        let expected = original.digest().unwrap();
        for change in 0..8 {
            let (context, mut account, mut key, mut nonce, mut amount, mut fee, mut output) =
                original.clone().into_parts();
            match change {
                0 => account = RewardAccountId::from_bytes([0x52; 64]),
                1..=3 => {
                    let mut bytes = *key.as_bytes();
                    bytes[[0, 1296, 2591][change - 1]] ^= 1;
                    key = EncodedMlDsa87PublicKey::from_bytes(bytes);
                }
                4 => nonce = WithdrawalNonce::new(nonce.value() ^ (1 << 32)),
                5 => amount = Amount::from_atoms(amount.atoms() + (1 << 64)).unwrap(),
                6 => fee = Amount::from_atoms(fee.atoms() + (1 << 64)).unwrap(),
                7 => output.0 = NoteCommitment::from_bytes([0x62; 64]),
                _ => unreachable!(),
            }
            let changed = RewardWithdrawalEncryptionCore::new(
                context, account, key, nonce, amount, fee, output,
            )
            .unwrap();
            assert_ne!(
                changed.digest().unwrap(),
                expected,
                "withdrawal change {change}"
            );
        }
    }

    #[test]
    fn payment_layout_rejects_unrepresentable_counts_without_allocating() {
        let max = usize::try_from(u32::MAX).unwrap();
        assert_eq!(payment_part_count(1, 1), Ok(14));
        assert_eq!(payment_part_count(2, 3), Ok(19));
        assert_eq!(payment_part_count(max - 13, 1), Ok(u32::MAX));
        assert_eq!(
            payment_part_count(max - 12, 1),
            Err(CryptoFramingError::TooManyParts)
        );
        assert_eq!(
            payment_part_count(1, max / 2),
            Err(CryptoFramingError::TooManyParts)
        );
        assert_eq!(
            payment_part_count(1, max),
            Err(CryptoFramingError::TooManyParts)
        );
        assert_eq!(
            payment_part_count(usize::MAX, 1),
            Err(CryptoFramingError::TooManyParts)
        );
        assert_eq!(
            payment_part_count(1, usize::MAX),
            Err(CryptoFramingError::TooManyParts)
        );
    }
}
