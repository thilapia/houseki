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
}
