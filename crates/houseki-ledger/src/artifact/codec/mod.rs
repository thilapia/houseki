//! Exact local V1 encodings with bounded decoding and no trust promotion.

mod archive;
mod limits;
mod reader;
mod records;
mod writer;

pub(crate) use archive::{decode_archive, encode_archive};
pub use limits::DecodeLimits;
pub use records::{
    decode_artifact_header, decode_effects, decode_fixture_stream, decode_fixture_unit,
    decode_occurrences, decode_policy, decode_receipts, decode_snapshot, encode_artifact_header,
    encode_effects, encode_fixture_stream, encode_fixture_unit, encode_occurrences, encode_policy,
    encode_receipts, encode_snapshot,
};

/// Independent record offsets and hostile representation declarations.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::{manifest, payment_body, trusted_manifest};
    use crate::{SnapshotRecord, validate_bootstrap};
    use houseki_types::{
        EncodedTransactionProof, ExecutionOutcome, ExecutionRejectionReason as R, Occurrence,
        PaymentEnvelope, Receipt, ValidatorId, VertexId,
    };

    /// Creates one complete unverified occurrence with a three byte proof.
    fn occurrence() -> Occurrence {
        Occurrence::new(
            VertexId::from_bytes([1; 64]),
            ValidatorId::from_bytes([2; 64]),
            manifest().committee_context,
            u64::MAX,
            PaymentEnvelope::new(
                payment_body(1, 1),
                EncodedTransactionProof::new(vec![5, 6, 7], 3).unwrap(),
            )
            .into(),
        )
    }

    /// Pins independently counted offsets rather than relying only on round trips.
    #[test]
    fn record_vectors_match_independent_offsets() {
        let bytes = encode_occurrences(&[occurrence()]).unwrap();

        assert_eq!(&bytes[..8], &1_u64.to_le_bytes());
        assert_eq!(&bytes[16..80], &[1; 64]);
        assert_eq!(&bytes[80..144], &[2; 64]);
        assert_eq!(&bytes[216..224], &u64::MAX.to_le_bytes());
        assert_eq!(&bytes[232..236], &1_u32.to_le_bytes());
        assert_eq!(
            decode_occurrences(&bytes, DecodeLimits::reference()).unwrap(),
            vec![occurrence()]
        );
    }

    /// Includes the outer count and every occurrence length prefix in component
    /// accounting.
    #[test]
    fn component_bytes_include_every_prefix() {
        assert_eq!(encode_occurrences(&[]).unwrap(), 0_u64.to_le_bytes());

        let bytes = encode_occurrences(&[occurrence()]).unwrap();
        let record_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap());

        assert_eq!(bytes.len() as u64, 16 + record_len);
        assert_eq!(
            encode_occurrences(&[occurrence(), occurrence()])
                .unwrap()
                .len(),
            8 + 2 * (bytes.len() - 8)
        );
    }

    /// Assigns canonical rejection codes independently of evaluation precedence.
    #[test]
    fn receipt_codes_are_explicit() {
        let reasons = [
            R::UnsupportedContext,
            R::OutsideValidityRange,
            R::DisallowedAnchor,
            R::WrongFeeSchedule,
            R::WrongFee,
            R::SpentNullifier,
            R::InsufficientBalance,
            R::WrongNonce,
            R::NonceExhausted,
            R::StateBoundsExceeded,
        ];

        for (i, reason) in reasons.into_iter().enumerate() {
            let receipt = Receipt::new(
                VertexId::from_bytes([1; 64]),
                u64::MAX,
                ExecutionOutcome::Rejected(reason),
            );

            let bytes = encode_receipts(&[receipt]).unwrap();

            assert_eq!(&bytes[88..92], &2_u32.to_le_bytes());
            assert_eq!(&bytes[92..96], &((i + 1) as u32).to_le_bytes());
            assert_eq!(
                decode_receipts(&bytes, DecodeLimits::reference()).unwrap(),
                vec![receipt]
            );
        }

        let accepted = Receipt::new(VertexId::from_bytes([1; 64]), 0, ExecutionOutcome::Accepted);

        assert_eq!(
            &encode_receipts(&[accepted]).unwrap()[88..96],
            &[1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    /// Every V1 record matches bytes built by the independent Python implementation.
    #[test]
    fn all_record_fixtures_are_canonical() {
        let limits = DecodeLimits::reference();
        let policy = include_bytes!("../../../fixtures/reference-v1/policy.bin");

        let decoded = decode_policy(policy, limits).unwrap();

        assert_eq!(decoded.payment_fee(&payment_body(4, 2)).unwrap().atoms(), 6);
        assert_eq!(encode_policy(&decoded).unwrap(), policy);

        let snapshot = include_bytes!("../../../fixtures/reference-v1/snapshot.bin");

        let decoded = decode_snapshot(snapshot, limits).unwrap();

        assert_eq!(
            decoded.accounts[0].1.next_nonce().value(),
            0x0102030405060708
        );
        assert_eq!(
            decoded.committee[0].weight(),
            0x0102030405060708090a0b0c0d0e0f10
        );
        assert_eq!(encode_snapshot(&decoded).unwrap(), snapshot);

        let occurrences = include_bytes!("../../../fixtures/reference-v1/occurrences.bin");

        assert_eq!(encode_occurrences(&[occurrence()]).unwrap(), occurrences);

        let receipts = include_bytes!("../../../fixtures/reference-v1/receipts.bin");

        assert_eq!(
            encode_receipts(&decode_receipts(receipts, limits).unwrap()).unwrap(),
            receipts
        );

        let effects = include_bytes!("../../../fixtures/reference-v1/effects.bin");

        let decoded = decode_effects(effects, limits).unwrap();

        assert_eq!(
            decoded[0].accepted.as_ref().unwrap().appends[0]
                .position
                .value(),
            0x0102030405060708
        );
        assert_eq!(encode_effects(&decoded).unwrap(), effects);

        let header = include_bytes!("../../../fixtures/reference-v1/artifact_header.bin");

        let decoded = decode_artifact_header(header, limits).unwrap();

        assert_eq!(decoded.sequence.value(), 0x0102030405060708);
        assert_eq!(encode_artifact_header(&decoded).unwrap(), header);

        let unit = include_bytes!("../../../fixtures/reference-v1/fixture_unit.bin");

        assert_eq!(
            encode_fixture_unit(&decode_fixture_unit(unit, limits).unwrap()).unwrap(),
            unit
        );

        let stream = include_bytes!("../../../fixtures/reference-v1/fixture_stream.bin");

        assert_eq!(
            encode_fixture_stream(&decode_fixture_stream(stream, limits).unwrap()).unwrap(),
            stream
        );
    }

    /// One decoder's acceptance predicate for common malformed input checks.
    type DecoderAccepts = fn(&[u8], DecodeLimits) -> bool;

    /// Rejects inverted source offsets through the public encoder rather than
    /// panicking.
    #[test]
    fn inverted_header_offsets_are_rejected() {
        let mut header = decode_artifact_header(
            include_bytes!("../../../fixtures/reference-v1/artifact_header.bin"),
            DecodeLimits::reference(),
        )
        .unwrap();
        header.order.start_offset = 2;
        header.order.end_offset = 1;

        assert!(encode_artifact_header(&header).is_err());
    }

    /// Unknown schema values and malformed nested counts fail without panicking.
    #[test]
    fn every_decoder_rejects_bad_prefixes_and_extensions() {
        let limits = DecodeLimits::reference();

        let cases: &[(&[u8], DecoderAccepts)] = &[
            (
                include_bytes!("../../../fixtures/reference-v1/policy.bin"),
                |b, l| decode_policy(b, l).is_ok(),
            ),
            (
                include_bytes!("../../../fixtures/reference-v1/snapshot.bin"),
                |b, l| decode_snapshot(b, l).is_ok(),
            ),
            (
                include_bytes!("../../../fixtures/reference-v1/effects.bin"),
                |b, l| decode_effects(b, l).is_ok(),
            ),
            (
                include_bytes!("../../../fixtures/reference-v1/artifact_header.bin"),
                |b, l| decode_artifact_header(b, l).is_ok(),
            ),
            (
                include_bytes!("../../../fixtures/reference-v1/fixture_unit.bin"),
                |b, l| decode_fixture_unit(b, l).is_ok(),
            ),
            (
                include_bytes!("../../../fixtures/reference-v1/fixture_stream.bin"),
                |b, l| decode_fixture_stream(b, l).is_ok(),
            ),
        ];
        for (bytes, accepts) in cases {
            for length in [0, 1, 7, bytes.len() - 1] {
                assert!(!accepts(&bytes[..length], limits));
            }

            let mut extended = bytes.to_vec();
            extended.push(0);

            assert!(!accepts(&extended, limits));
            assert!(!accepts(
                bytes,
                DecodeLimits {
                    max_bytes: bytes.len() - 1,
                    max_records: 4096
                }
            ));
        }

        let mut policy = include_bytes!("../../../fixtures/reference-v1/policy.bin").to_vec();
        let len = policy.len();
        policy[len - 4..].copy_from_slice(&2_u32.to_le_bytes());

        assert!(decode_policy(&policy, limits).is_err());
    }

    /// Commits complete authorization bytes, preserving identical semantic bodies.
    #[test]
    fn envelope_binding_includes_proof_signature_and_ciphertext() {
        use houseki_types::{
            Amount, EncodedMlDsa87PublicKey, EncodedMlDsa87Signature, RewardAccountId,
            RewardWithdrawalBody, RewardWithdrawalEnvelope, WithdrawalNonce,
        };
        let original = occurrence();
        let (vertex, author, committee, index, _) = original.clone().into_parts();
        let changed = Occurrence::new(
            vertex,
            author,
            committee,
            index,
            PaymentEnvelope::new(
                payment_body(1, 1),
                EncodedTransactionProof::new(vec![5, 6, 8], 3).unwrap(),
            )
            .into(),
        );

        assert_ne!(
            encode_occurrences(std::slice::from_ref(&original)).unwrap(),
            encode_occurrences(&[changed]).unwrap()
        );

        let body = payment_body(1, 1);
        let withdrawal = RewardWithdrawalBody::new(
            body.context(),
            RewardAccountId::from_bytes([1; 64]),
            EncodedMlDsa87PublicKey::from_bytes([2; 2592]),
            WithdrawalNonce::new(0),
            Amount::from_atoms(3).unwrap(),
            Amount::from_atoms(1).unwrap(),
            body.outputs().outputs()[0].clone(),
        )
        .unwrap();
        let make = |byte| {
            Occurrence::new(
                vertex,
                author,
                committee,
                index,
                RewardWithdrawalEnvelope::new(
                    withdrawal.clone(),
                    EncodedTransactionProof::new(vec![5], 1).unwrap(),
                    EncodedMlDsa87Signature::from_bytes([byte; 4627]),
                )
                .into(),
            )
        };

        let first = encode_occurrences(&[make(0)]).unwrap();

        assert_eq!(&first[232..236], &2_u32.to_le_bytes());
        assert_ne!(first, encode_occurrences(&[make(1)]).unwrap());
        assert_eq!(
            decode_occurrences(&first, DecodeLimits::reference()).unwrap(),
            vec![make(0)]
        );

        let mut ciphertext = encode_occurrences(&[original]).unwrap();
        ciphertext[244 + 196 + 64 + 64] ^= 1;

        assert_ne!(
            decode_occurrences(&ciphertext, DecodeLimits::reference()).unwrap(),
            vec![occurrence()]
        );
    }

    /// Rejects extreme lengths before allocation as well as truncation and extensions.
    #[test]
    fn decode_rejects_hostile_lengths() {
        assert!(decode_occurrences(&u64::MAX.to_le_bytes(), DecodeLimits::reference()).is_err());

        let bytes = encode_occurrences(&[occurrence()]).unwrap();
        for length in [0, 7, 15, 231, bytes.len() - 1] {
            assert!(decode_occurrences(&bytes[..length], DecodeLimits::reference()).is_err());
        }

        let mut extra = bytes.clone();
        extra.push(0);

        assert!(decode_occurrences(&extra, DecodeLimits::reference()).is_err());

        let mut huge = bytes;
        huge[8..16].copy_from_slice(&u64::MAX.to_le_bytes());

        assert!(decode_occurrences(&huge, DecodeLimits::reference()).is_err());
    }

    /// Complete key sorting removes host insertion order from reference bytes.
    #[test]
    fn snapshot_sorting_is_canonical() {
        let parent = validate_bootstrap(trusted_manifest())
            .unwrap()
            .into_snapshot();
        let mut record = SnapshotRecord::from_state(parent.state()).unwrap();
        record.spent = vec![
            houseki_types::Nullifier::from_bytes([2; 64]),
            houseki_types::Nullifier::from_bytes([1; 64]),
        ];

        let first = encode_snapshot(&record).unwrap();
        record.spent.reverse();

        assert_eq!(encode_snapshot(&record).unwrap(), first);

        record.spent.push(record.spent[0]);

        assert!(encode_snapshot(&record).is_err());
    }
}
