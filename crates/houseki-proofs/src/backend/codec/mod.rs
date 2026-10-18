//! Canonical fixed shape proof encoding with validation before decoded allocation.

mod decode;
mod encode;
mod error;
mod layout;
mod reader;
mod writer;

pub(crate) use decode::decode;
#[cfg_attr(
    not(any(test, feature = "prover")),
    expect(unused_imports, reason = "reserved for private family dispatch")
)]
pub(crate) use encode::encode;
pub(crate) use error::CodecError;
pub(crate) use layout::Layout;

/// Complete fixed header including the payload length.
const HEADER_BYTES: usize = 96;

/// Bound on requested decoded vector storage, including all nested vector headers.
pub(crate) const MAX_DECODED_BYTES: usize = 16 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    /// Exact vector payload budget from the last successful scan, excluding allocator ownership headers.
    static DECODED_VECTOR_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts the exact canonical size of a valid generated proof for test resource measurements.
///
/// This observer allocates and encodes nothing and does not alter either codec cap.
#[cfg(test)]
pub(crate) fn measured_size(layout: Layout, proof: &crate::backend::config::BackendProof) -> usize {
    let rounds = layout.log_rows + 1;
    let chunks = layout.quotient_chunks;
    let width = layout.width;
    let main_points = if layout.main_next { 2 } else { 1 };
    let mut bytes = 96 + 8 + 3 * 64 + main_points * width * 24 + chunks * 72 + 72;
    bytes += 72 * (1 + main_points + chunks) + rounds * 64;
    bytes += 128 * 8 * (6 + width + 3 + chunks * 6);
    bytes += 128 * 32 * (2 + chunks);
    let fri = &proof.opening_proof.1;
    for opening in &fri.input_openings {
        bytes += 4 + 64 * opening.opening_proof.1.sibling_hashes.len();
    }

    bytes += rounds * 128 * (24 + 32);
    for opening in &fri.commit_phase_openings {
        bytes += 4 + 64 * opening.opening_proof.1.sibling_hashes.len();
    }

    bytes + 24
}

/// Real proof encoding and hostile input boundary tests.
#[cfg(test)]
mod tests {
    use super::decode::decode_pass;
    use super::*;
    use crate::test_allocator as allocation;
    use crate::{
        ProofRuntime,
        backend::{
            prover,
            square_air::{SquareAir, trace},
            verifier,
        },
        profile::{ExpectedIdentity, Relation},
    };
    use houseki_types::ProofProfileId;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    /// Trusted dimensions for a synthetic relation that has no production dispatch entry.
    fn layout() -> Layout {
        Layout {
            log_rows: 9,
            width: 1,
            quotient_chunks: 4,
            main_next: true,
        }
    }

    /// Names the synthetic codec fixture separately from every transaction profile.
    fn identity() -> ExpectedIdentity {
        ExpectedIdentity {
            profile: ProofProfileId::new(0xffff0004),
            relation: Relation::Payment,
            shape: 0x0101,
            manifest: [0x53; 64],
        }
    }

    /// Round trips real randomized proofs and rejects noncanonical or oversized structure.
    #[test]
    fn real_proofs_round_trip_through_bounded_codec() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let public = [Goldilocks::from_u64(289)];

        let proof = prover::prove(
            &lease,
            b"houseki/test/codec/v1",
            &SquareAir,
            trace(),
            &public,
        )
        .unwrap();
        let encoded = encode(&identity(), layout(), &proof).unwrap();
        assert_eq!(measured_size(layout(), &proof), encoded.as_bytes().len());
        let decoded = decode(&identity(), layout(), encoded.as_bytes()).unwrap();

        verifier::verify(
            &lease,
            b"houseki/test/codec/v1",
            &SquareAir,
            &decoded,
            &public,
        )
        .unwrap();
        assert!(
            verifier::verify(
                &lease,
                b"houseki/test/codec/v1",
                &SquareAir,
                &decoded,
                &[Goldilocks::from_u64(290)]
            )
            .is_err()
        );
        assert_eq!(
            encode(&identity(), layout(), &decoded).unwrap().as_bytes(),
            encoded.as_bytes()
        );
        assert_eq!(&encoded.as_bytes()[..8], b"HKPROOF1");
        assert_eq!(
            &encoded.as_bytes()[8..24],
            &[1, 0, 0, 0, 4, 0, 255, 255, 1, 0, 0, 0, 1, 1, 0, 0]
        );

        for length in [0, 7, 95, 96, encoded.byte_len() - 1] {
            assert!(decode(&identity(), layout(), &encoded.as_bytes()[..length]).is_err());
        }

        let mut trailing = encoded.as_bytes().to_vec();
        trailing.push(0);

        assert!(matches!(
            decode(&identity(), layout(), &trailing),
            Err(CodecError::LengthMismatch)
        ));

        for (offset, value, expected) in [
            (8, 2, CodecError::UnsupportedVersion),
            (12, 3, CodecError::IdentityMismatch),
            (16, 2, CodecError::IdentityMismatch),
            (20, 3, CodecError::IdentityMismatch),
            (96, 31, CodecError::InvalidShape),
        ] {
            let mut changed = encoded.as_bytes().to_vec();
            changed[offset] = value;

            assert!(
                matches!(decode(&identity(), layout(), &changed), Err(error) if error == expected)
            );
        }

        let mut changed = encoded.as_bytes().to_vec();
        changed[88..96].copy_from_slice(&u64::MAX.to_le_bytes());

        assert!(matches!(
            decode(&identity(), layout(), &changed),
            Err(CodecError::LengthMismatch)
        ));

        let mut changed = encoded.as_bytes().to_vec();
        changed[296..304].copy_from_slice(&18446744069414584321_u64.to_le_bytes());

        assert!(matches!(
            decode(&identity(), layout(), &changed),
            Err(CodecError::NonCanonicalField)
        ));
    }

    /// Builds a complete structural vector with literal wire dimensions and no valid proof claim.
    fn structural_vector() -> Vec<u8> {
        let mut bytes = vec![0; 132_996];
        bytes[..8].copy_from_slice(b"HKPROOF1");
        bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0xffff0004_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&0x0101_u32.to_le_bytes());
        bytes[24..88].fill(0x53);
        bytes[88..96].copy_from_slice(&132_900_u64.to_le_bytes());
        bytes[96..100].copy_from_slice(&10_u32.to_le_bytes());
        bytes[100..104].copy_from_slice(&4_u32.to_le_bytes());

        bytes
    }

    /// Matches an independently framed full structural vector and measures both decoder passes.
    #[test]
    fn canonical_vector_scans_without_allocating() {
        let bytes = structural_vector();

        let (scanned, scan_calls, scan_bytes) =
            allocation::measure(|| decode_pass(layout(), &bytes[96..], false));

        assert!(matches!(scanned, Ok(None)));
        assert_eq!((scan_calls, scan_bytes), (0, 0));

        let (decoded, calls, allocated) =
            allocation::measure(|| decode(&identity(), layout(), &bytes));
        let decoded = decoded.unwrap();

        assert!(calls > 0);
        assert!(allocated < MAX_DECODED_BYTES);
        assert_eq!(
            encode(&identity(), layout(), &decoded).unwrap().as_bytes(),
            bytes
        );

        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();

        assert!(
            verifier::verify(
                &lease,
                b"structural-only",
                &SquareAir,
                &decoded,
                &[Goldilocks::from_u64(289)]
            )
            .is_err()
        );
    }

    /// Rejects hostile lengths, fields and dimensions before a single allocator request.
    #[test]
    fn malformed_payloads_allocate_nothing() {
        let bytes = structural_vector();
        let mut cases = Vec::new();
        for length in [96, 97, 103, 295, 297, 12_089, 20_285, 61_249, 132_995] {
            let mut truncated = bytes[..length].to_vec();
            truncated[88..96].copy_from_slice(&((length - 96) as u64).to_le_bytes());
            cases.push((truncated, CodecError::Truncated));
        }

        for offset in [12_088, 20_284, 61_248, 68_420, 132_968] {
            let mut changed = bytes.clone();
            changed[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            cases.push((changed, CodecError::InvalidShape));
        }

        for offset in [296, 132_988] {
            let mut changed = bytes.clone();
            changed[offset..offset + 8]
                .copy_from_slice(&18_446_744_069_414_584_321_u64.to_le_bytes());
            cases.push((changed, CodecError::NonCanonicalField));
        }

        for offset in [96, 100] {
            let mut changed = bytes.clone();
            changed[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            cases.push((changed, CodecError::InvalidShape));
        }

        let mut changed = bytes.clone();
        changed.push(0);
        changed[88..96].copy_from_slice(&132_901_u64.to_le_bytes());
        cases.push((changed, CodecError::TrailingBytes));

        for (bytes, expected) in cases {
            let (result, calls, allocated) =
                allocation::measure(|| decode(&identity(), layout(), &bytes));

            assert!(matches!(result, Err(error) if error == expected));
            assert_eq!((calls, allocated), (0, 0));
        }
    }

    /// Refuses object fields omitted from the canonical zero grinding payload.
    #[test]
    fn encoding_rejects_unrepresented_fields() {
        let bytes = structural_vector();
        let mut proof = decode(&identity(), layout(), &bytes).unwrap();

        proof.ood_pow_witness = Goldilocks::ONE;

        assert!(matches!(
            encode(&identity(), layout(), &proof),
            Err(CodecError::InvalidShape)
        ));

        proof.ood_pow_witness = Goldilocks::ZERO;
        proof.opening_proof.1.query_pow_witness = Goldilocks::ONE;

        assert!(matches!(
            encode(&identity(), layout(), &proof),
            Err(CodecError::InvalidShape)
        ));

        proof.opening_proof.1.query_pow_witness = Goldilocks::ZERO;
        proof.opened_values.preprocessed = Some(p3_uni_stark::PreprocessedOpenedValues {
            local: vec![],
            next: None,
        });

        assert!(matches!(
            encode(&identity(), layout(), &proof),
            Err(CodecError::InvalidShape)
        ));

        proof.opened_values.preprocessed = None;
        proof.opening_proof.1.commit_phase_openings.pop();

        assert!(matches!(
            encode(&identity(), layout(), &proof),
            Err(CodecError::InvalidShape)
        ));
    }

    /// Rejects an empty payload under an independently encoded header without allocating it.
    #[test]
    fn header_requires_the_complete_expected_identity_and_payload() {
        let mut bytes = [0_u8; 96];
        bytes[..8].copy_from_slice(b"HKPROOF1");
        bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0xffff0004_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&0x0101_u32.to_le_bytes());
        bytes[24..88].fill(0x53);

        assert!(matches!(
            decode(&identity(), layout(), &bytes),
            Err(CodecError::Truncated)
        ));

        let huge = vec![0; 2_097_153];

        assert!(matches!(
            decode(&identity(), layout(), &huge),
            Err(CodecError::ProofTooLarge)
        ));
    }

    /// Maximum valid frontiers decode within the independent vector budget for all eight shapes.
    #[test]
    fn payment_worst_case_encoding_and_decoded_storage_are_bounded() {
        use crate::{
            circuits::payment::PaymentLayout,
            profile::payment::{SupportedPaymentShape, identity},
        };
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let shape = SupportedPaymentShape::new(inputs, outputs).unwrap();
                let layout = PaymentLayout::for_shape(shape).unwrap().codec();
                let identity = identity(shape);
                let (bytes, _) = payment_structural_vector(&identity, layout);
                assert_eq!(bytes.len(), layout.encoded_upper_bound().unwrap());
                let (decoded, calls, allocated) =
                    allocation::measure(|| decode(&identity, layout, &bytes));
                let decoded = decoded.unwrap();
                let payload = DECODED_VECTOR_BYTES.with(|bytes| bytes.get());
                assert!(payload <= layout.decoded_upper_bound().unwrap());
                assert!(payload <= MAX_DECODED_BYTES);
                assert!(allocated - payload >= calls * size_of::<usize>());
                #[cfg(target_pointer_width = "64")]
                assert_eq!(allocated, payload + calls * 8);
                assert_eq!(
                    encode(&identity, layout, &decoded).unwrap().as_bytes(),
                    bytes
                );
            }
        }
    }

    /// Extra frontier nodes fail before allocation even when the complete envelope fits the cap.
    #[test]
    fn payment_excess_frontiers_cannot_exceed_decoded_bound() {
        use crate::{
            circuits::payment::PaymentLayout,
            profile::payment::{SupportedPaymentShape, identity},
        };
        let shape = SupportedPaymentShape::new(1, 1).unwrap();
        let layout = PaymentLayout::for_shape(shape).unwrap().codec();
        let expected = identity(shape);
        let (bytes, frontiers) = payment_structural_vector(&expected, layout);
        for offset in frontiers {
            let mut changed = bytes.clone();
            let count = u32::from_le_bytes(changed[offset..offset + 4].try_into().unwrap());
            changed[offset..offset + 4].copy_from_slice(&(count + 4).to_le_bytes());
            changed.splice(offset + 4..offset + 4, [0; 256]);
            let length = changed.len() - HEADER_BYTES;
            changed[88..96].copy_from_slice(&(length as u64).to_le_bytes());
            assert!(changed.len() < crate::profile::MAX_PROOF_BYTES);
            let (result, calls, allocated) =
                allocation::measure(|| decode(&expected, layout, &changed));
            assert!(matches!(result, Err(CodecError::InvalidShape)));
            assert_eq!((calls, allocated), (0, 0));
        }

        let mut proof = decode(&expected, layout, &bytes).unwrap();
        for fri in [false, true] {
            let original = frontier(&mut proof, fri).len();
            frontier(&mut proof, fri).resize(original + 4, [0; 8]);
            let (result, calls, allocated) =
                allocation::measure(|| encode(&expected, layout, &proof));
            assert!(matches!(result, Err(CodecError::InvalidShape)));
            assert_eq!((calls, allocated), (0, 0));
            frontier(&mut proof, fri).truncate(original);
        }
    }

    /// Equal public lengths and equal trace dimensions never substitute for exact shape identity.
    #[test]
    fn payment_hostile_headers_and_dimensions_allocate_nothing() {
        use crate::{
            circuits::payment::PaymentLayout,
            profile::payment::{SupportedPaymentShape, identity},
        };
        let shape = SupportedPaymentShape::new(4, 2).unwrap();
        let layout = PaymentLayout::for_shape(shape).unwrap().codec();
        let expected = identity(shape);
        let (bytes, frontiers) = payment_structural_vector(&expected, layout);
        let mut cases = Vec::new();
        for offset in [12, 16, 20, 24, 96, 100] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            cases.push(changed);
        }

        for offset in frontiers {
            let mut changed = bytes.clone();
            changed[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            cases.push(changed);
        }

        let mut noncanonical = bytes.clone();
        noncanonical[296..304].copy_from_slice(&18_446_744_069_414_584_321_u64.to_le_bytes());
        cases.push(noncanonical);
        let mut trailing = bytes.clone();
        trailing.push(0);
        let length = trailing.len() - 96;
        trailing[88..96].copy_from_slice(&(length as u64).to_le_bytes());
        cases.push(trailing);
        let mut truncated = bytes[..bytes.len() / 2].to_vec();
        let length = truncated.len() - 96;
        truncated[88..96].copy_from_slice(&(length as u64).to_le_bytes());
        cases.push(truncated);
        for bytes in cases {
            let (result, calls, allocated) =
                allocation::measure(|| decode(&expected, layout, &bytes));
            assert!(result.is_err());
            assert_eq!((calls, allocated), (0, 0));
        }

        for ((left_i, left_o), (right_i, right_o)) in [
            ((1, 2), (2, 1)),
            ((2, 2), (3, 1)),
            ((3, 2), (4, 1)),
            ((4, 1), (4, 2)),
        ] {
            let left = SupportedPaymentShape::new(left_i, left_o).unwrap();
            let right = SupportedPaymentShape::new(right_i, right_o).unwrap();
            let (bytes, _) = payment_structural_vector(
                &identity(left),
                PaymentLayout::for_shape(left).unwrap().codec(),
            );
            let (result, calls, allocated) = allocation::measure(|| {
                decode(
                    &identity(right),
                    PaymentLayout::for_shape(right).unwrap().codec(),
                    &bytes,
                )
            });
            assert!(matches!(result, Err(CodecError::IdentityMismatch)));
            assert_eq!((calls, allocated), (0, 0));
        }
    }

    /// Writes a public zero-valued structural object directly from the independent wire grammar.
    ///
    /// This is an encoding fixture rather than a cryptographically valid proof.
    fn payment_structural_vector(
        identity: &ExpectedIdentity,
        layout: Layout,
    ) -> (Vec<u8>, Vec<usize>) {
        let mut bytes = identity.to_bytes().to_vec();
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&(layout.degree_bits() as u32).to_le_bytes());
        bytes.extend_from_slice(&(layout.quotient_chunks as u32).to_le_bytes());
        zeros(&mut bytes, 3 * 64);
        zeros(&mut bytes, layout.points(1) * layout.width * 24);
        zeros(&mut bytes, (layout.quotient_chunks + 1) * 72);
        for batch in 0..3 {
            zeros(
                &mut bytes,
                layout.matrices(batch) * layout.points(batch) * 72,
            );
        }

        zeros(&mut bytes, layout.degree_bits() * 64);
        let mut frontiers = Vec::new();
        for batch in 0..3 {
            zeros(
                &mut bytes,
                128 * layout.matrices(batch) * layout.committed_width(batch) * 8,
            );
            zeros(&mut bytes, 128 * layout.matrices(batch) * 32);
            let count = super::layout::frontier_maximum(layout.input_height());
            frontiers.push(bytes.len());
            bytes.extend_from_slice(&(count as u32).to_le_bytes());
            zeros(&mut bytes, count * 64);
        }

        for round in 0..layout.degree_bits() {
            zeros(&mut bytes, 128 * (24 + 32));
            let count = super::layout::frontier_maximum(layout.input_height() - round - 1);
            frontiers.push(bytes.len());
            bytes.extend_from_slice(&(count as u32).to_le_bytes());
            zeros(&mut bytes, count * 64);
        }

        zeros(&mut bytes, 24);
        let length = bytes.len() - 96;
        bytes[88..96].copy_from_slice(&(length as u64).to_le_bytes());
        (bytes, frontiers)
    }

    /// Appends public zero scalar encodings without reusing the production encoder's traversal.
    fn zeros(bytes: &mut Vec<u8>, count: usize) {
        bytes.resize(bytes.len() + count, 0);
    }

    /// Both commitment and FRI frontiers reject omitted and redundant authentication nodes.
    #[test]
    fn real_frontiers_reject_missing_and_redundant_nodes() {
        let runtime = ProofRuntime::new();
        let admission = runtime.acquire().unwrap();
        let public = [Goldilocks::from_u64(289)];
        let prefix = b"houseki/test/frontier-canonicality/v1";
        let mut proof = prover::prove(&admission, prefix, &SquareAir, trace(), &public).unwrap();
        for fri in [false, true] {
            let removed = frontier(&mut proof, fri).pop().unwrap();
            let encoded = encode(&identity(), layout(), &proof).unwrap();
            let decoded = decode(&identity(), layout(), encoded.as_bytes()).unwrap();
            assert!(verifier::verify(&admission, prefix, &SquareAir, &decoded, &public).is_err());
            frontier(&mut proof, fri).push(removed);
            frontier(&mut proof, fri).push([0; 8]);
            let encoded = encode(&identity(), layout(), &proof).unwrap();
            let decoded = decode(&identity(), layout(), encoded.as_bytes()).unwrap();
            assert!(verifier::verify(&admission, prefix, &SquareAir, &decoded, &public).is_err());
            frontier(&mut proof, fri).pop();
        }

        assert!(verifier::verify(&admission, prefix, &SquareAir, &proof, &public).is_ok());
    }

    /// Selects one authenticated public frontier without changing the proof's other fields.
    fn frontier(proof: &mut crate::backend::config::BackendProof, fri: bool) -> &mut Vec<[u64; 8]> {
        if fri {
            &mut proof.opening_proof.1.commit_phase_openings[0]
                .opening_proof
                .1
                .sibling_hashes
        } else {
            &mut proof.opening_proof.1.input_openings[1]
                .opening_proof
                .1
                .sibling_hashes
        }
    }
}
