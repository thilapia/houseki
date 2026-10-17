//! Canonical fixed shape proof encoding with validation before decoded allocation.

#[cfg(test)]
use crate::test_allocator as allocation;
mod reader;
mod writer;

use houseki_types::EncodedTransactionProof;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::PrunedMerklePaths;
use p3_uni_stark::{Commitments, OpenedValues};

use super::config::{BackendProof, EXTENSION_DEGREE, LOG_BLOWUP, QUERIES, SALT_ELEMENTS};
use crate::profile::{ExpectedIdentity, MAX_PROOF_BYTES};
use reader::Reader;
use writer::{Writer, exact};

/// Complete fixed header including the payload length.
const HEADER_BYTES: usize = 96;

/// Bound on requested decoded vector storage, including all nested vector headers.
const MAX_DECODED_BYTES: usize = 16 * 1024 * 1024;

/// Failures detected without interpreting a malformed object as a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CodecError {
    /// The complete encoded proof exceeds its inclusive byte cap.
    #[error("proof exceeds byte limit")]
    ProofTooLarge,

    /// Required canonical bytes are missing.
    #[error("truncated proof")]
    Truncated,

    /// The complete wire version is unsupported.
    #[error("unsupported proof version")]
    UnsupportedVersion,

    /// A header disagrees with the independently selected identity.
    #[error("proof identity mismatch")]
    IdentityMismatch,

    /// The declared payload length disagrees with the actual remaining bytes.
    #[error("proof length mismatch")]
    LengthMismatch,

    /// A base field word is not its unique canonical representative.
    #[error("noncanonical field element")]
    NonCanonicalField,

    /// Proof dimensions disagree with the trusted layout or a fixed backend rule.
    #[error("invalid proof shape")]
    InvalidShape,

    /// Bytes remain after the exact expected payload.
    #[error("trailing proof bytes")]
    TrailingBytes,

    /// Checked vector storage would exceed the decoder's allocation budget.
    #[error("decoded proof exceeds allocation limit")]
    AllocationLimit,

    /// The allocator could not reserve already bounded public proof storage.
    #[error("proof allocation failed")]
    AllocationFailed,
}

/// Trusted shape metadata for the fixed backend without preprocessed commitments.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Layout {
    /// Logarithm of the original trace height before hiding interleaving.
    pub(crate) log_rows: usize,

    /// Exact number of main trace columns.
    pub(crate) width: usize,

    /// Exact power of two count of randomized quotient chunks.
    pub(crate) quotient_chunks: usize,

    /// Whether the AIR requires a second main trace opening.
    pub(crate) main_next: bool,
}

impl Layout {
    /// Rejects unsupported geometry before any payload driven loop or allocation.
    fn validate(self) -> Result<(), CodecError> {
        if !(9..=28).contains(&self.log_rows)
            || self.width == 0
            || self.width > MAX_PROOF_BYTES / 8
            || self.quotient_chunks < 2
            || !self.quotient_chunks.is_power_of_two()
            || self.quotient_chunks > MAX_PROOF_BYTES / 8
        {
            return Err(CodecError::InvalidShape);
        }
        Ok(())
    }

    /// Returns the interleaved commitment degree and binary FRI round count.
    fn degree_bits(self) -> usize {
        self.log_rows + 1
    }

    /// Returns the maximum binary input commitment height after low degree extension.
    fn input_height(self) -> usize {
        self.degree_bits() + LOG_BLOWUP
    }

    /// Returns the exact matrix count in a random, trace or quotient opening batch.
    fn matrices(self, batch: usize) -> usize {
        if batch == 2 { self.quotient_chunks } else { 1 }
    }

    /// Returns the exact OOD point count for one opening batch.
    fn points(self, batch: usize) -> usize {
        if batch == 1 && self.main_next { 2 } else { 1 }
    }

    /// Returns the committed width including the three hiding codewords.
    fn committed_width(self, batch: usize) -> usize {
        if batch == 1 {
            self.width + EXTENSION_DEGREE
        } else {
            2 * EXTENSION_DEGREE
        }
    }
}

/// Validates a fixed envelope against an identity resolved before untrusted decoding.
fn payload<'a>(identity: &ExpectedIdentity, bytes: &'a [u8]) -> Result<&'a [u8], CodecError> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(CodecError::ProofTooLarge);
    }
    let header = bytes.get(..HEADER_BYTES).ok_or(CodecError::Truncated)?;
    if &header[..8] != b"HKPROOF1" {
        return Err(CodecError::IdentityMismatch);
    }
    if header[8..12] != 1_u32.to_le_bytes() {
        return Err(CodecError::UnsupportedVersion);
    }
    if header[..88] != identity.to_bytes() {
        return Err(CodecError::IdentityMismatch);
    }
    let declared = u64::from_le_bytes(
        header[88..96]
            .try_into()
            .map_err(|_| CodecError::Truncated)?,
    );
    if declared != (bytes.len() - HEADER_BYTES) as u64 {
        return Err(CodecError::LengthMismatch);
    }
    Ok(&bytes[HEADER_BYTES..])
}

/// Scans a complete bounded payload before allocating any decoded vectors.
pub(crate) fn decode(
    identity: &ExpectedIdentity,
    layout: Layout,
    bytes: &[u8],
) -> Result<BackendProof, CodecError> {
    let payload = payload(identity, bytes)?;
    layout.validate()?;
    decode_pass(layout, payload, false)?;
    decode_pass(layout, payload, true)?.ok_or(CodecError::InvalidShape)
}

/// Parses the same fixed schema in allocation free and materializing modes.
fn decode_pass(
    layout: Layout,
    bytes: &[u8],
    materialize: bool,
) -> Result<Option<BackendProof>, CodecError> {
    let mut reader = Reader::new(bytes, materialize);
    exact(reader.u32()? as usize, layout.degree_bits())?;
    exact(reader.u32()? as usize, layout.quotient_chunks)?;
    let trace = reader.commitment()?;
    let quotient = reader.commitment()?;
    let random = reader.commitment()?;
    let trace_local = reader.extensions(layout.width)?;
    let trace_next = if layout.main_next {
        Some(reader.extensions(layout.width)?)
    } else {
        None
    };
    let quotient_chunks = reader.list(layout.quotient_chunks, |reader, _| {
        reader.extensions(EXTENSION_DEGREE)
    })?;
    let random_values = reader.extensions(EXTENSION_DEGREE)?;
    let hiding = reader.list(3, |reader, batch| {
        reader.list(layout.matrices(batch), |reader, _| {
            reader.list(layout.points(batch), |reader, _| {
                reader.extensions(EXTENSION_DEGREE)
            })
        })
    })?;
    let commits = reader.commitments(layout.degree_bits())?;
    let input_openings = reader.list(3, |reader, batch| {
        let opened_values = reader.list(QUERIES, |reader, _| {
            reader.list(layout.matrices(batch), |reader, _| {
                reader.fields(layout.committed_width(batch))
            })
        })?;
        let salts = reader.list(QUERIES, |reader, _| {
            reader.list(layout.matrices(batch), |reader, _| {
                reader.fields(SALT_ELEMENTS)
            })
        })?;
        let sibling_hashes = reader.siblings(QUERIES * layout.input_height())?;
        Ok(BatchMultiOpening {
            opened_values,
            opening_proof: (salts, PrunedMerklePaths { sibling_hashes }),
        })
    })?;
    let commit_phase_openings = reader.list(layout.degree_bits(), |reader, round| {
        let sibling_values = reader.list(QUERIES, |reader, _| reader.extensions(1))?;
        let salts = reader.list(QUERIES, |reader, _| {
            reader.list(1, |reader, _| reader.fields(SALT_ELEMENTS))
        })?;
        let sibling_hashes = reader.siblings(QUERIES * (layout.input_height() - round - 1))?;
        Ok(CommitPhaseMultiStep {
            sibling_values,
            opening_proof: (salts, PrunedMerklePaths { sibling_hashes }),
        })
    })?;
    let final_poly = reader.extensions(1)?;
    let commit_pow_witnesses = reader.list(layout.degree_bits(), |_, _| Ok(Goldilocks::ZERO))?;
    reader.finish()?;
    if !materialize {
        return Ok(None);
    }
    Ok(Some(BackendProof {
        commitments: Commitments {
            trace: trace.ok_or(CodecError::InvalidShape)?,
            quotient_chunks: quotient.ok_or(CodecError::InvalidShape)?,
            random,
        },
        opened_values: OpenedValues {
            trace_local,
            trace_next,
            preprocessed: None,
            quotient_chunks,
            random: Some(random_values),
        },
        opening_proof: (
            hiding,
            FriProof {
                batch_pow_witness: Goldilocks::ZERO,
                commit_phase_commits: commits,
                commit_pow_witnesses,
                input_openings,
                commit_phase_openings,
                final_poly,
                query_pow_witness: Goldilocks::ZERO,
            },
        ),
        degree_bits: layout.degree_bits(),
        ood_pow_witness: Goldilocks::ZERO,
    }))
}

/// Validates the complete object before allocating its canonical output bytes.
pub(crate) fn encode(
    identity: &ExpectedIdentity,
    layout: Layout,
    proof: &BackendProof,
) -> Result<EncodedTransactionProof, CodecError> {
    layout.validate()?;
    let mut measure = Writer::new(None)?;
    measure.bytes(&[0; HEADER_BYTES])?;
    encode_payload(&mut measure, layout, proof)?;
    let payload_length = measure.length - HEADER_BYTES;
    let mut writer = Writer::new(Some(measure.length))?;
    writer.bytes(&identity.to_bytes())?;
    writer.bytes(&(payload_length as u64).to_le_bytes())?;
    encode_payload(&mut writer, layout, proof)?;
    EncodedTransactionProof::new(writer.bytes, MAX_PROOF_BYTES)
        .map_err(|_| CodecError::ProofTooLarge)
}

/// Writes only the selected hiding shape and requires omitted zero grinding fields to be zero.
fn encode_payload(
    writer: &mut Writer,
    layout: Layout,
    proof: &BackendProof,
) -> Result<(), CodecError> {
    exact(proof.degree_bits, layout.degree_bits())?;
    if proof.ood_pow_witness != Goldilocks::ZERO || proof.opened_values.preprocessed.is_some() {
        return Err(CodecError::InvalidShape);
    }
    writer.u32(proof.degree_bits as u32)?;
    writer.u32(layout.quotient_chunks as u32)?;
    writer.commitment(&proof.commitments.trace)?;
    writer.commitment(&proof.commitments.quotient_chunks)?;
    writer.commitment(
        proof
            .commitments
            .random
            .as_ref()
            .ok_or(CodecError::InvalidShape)?,
    )?;
    let opened = &proof.opened_values;
    writer.extensions(&opened.trace_local, layout.width)?;
    match (&opened.trace_next, layout.main_next) {
        (Some(values), true) => writer.extensions(values, layout.width)?,
        (None, false) => {}
        _ => return Err(CodecError::InvalidShape),
    }
    exact(opened.quotient_chunks.len(), layout.quotient_chunks)?;
    for chunk in &opened.quotient_chunks {
        writer.extensions(chunk, EXTENSION_DEGREE)?;
    }
    writer.extensions(
        opened.random.as_ref().ok_or(CodecError::InvalidShape)?,
        EXTENSION_DEGREE,
    )?;
    let (hiding, fri) = &proof.opening_proof;
    exact(hiding.len(), 3)?;
    for (batch, matrices) in hiding.iter().enumerate() {
        exact(matrices.len(), layout.matrices(batch))?;
        for points in matrices {
            exact(points.len(), layout.points(batch))?;
            for values in points {
                writer.extensions(values, EXTENSION_DEGREE)?;
            }
        }
    }
    exact(fri.commit_phase_commits.len(), layout.degree_bits())?;
    exact(fri.commit_pow_witnesses.len(), layout.degree_bits())?;
    if fri.batch_pow_witness != Goldilocks::ZERO
        || fri.query_pow_witness != Goldilocks::ZERO
        || fri
            .commit_pow_witnesses
            .iter()
            .any(|value| *value != Goldilocks::ZERO)
    {
        return Err(CodecError::InvalidShape);
    }
    for cap in &fri.commit_phase_commits {
        writer.commitment(cap)?;
    }
    exact(fri.input_openings.len(), 3)?;
    for (batch, opening) in fri.input_openings.iter().enumerate() {
        exact(opening.opened_values.len(), QUERIES)?;
        for query in &opening.opened_values {
            exact(query.len(), layout.matrices(batch))?;
            for values in query {
                writer.fields(values, layout.committed_width(batch))?;
            }
        }
        exact(opening.opening_proof.0.len(), QUERIES)?;
        for query in &opening.opening_proof.0 {
            exact(query.len(), layout.matrices(batch))?;
            for salt in query {
                writer.fields(salt, SALT_ELEMENTS)?;
            }
        }
        writer.siblings(
            &opening.opening_proof.1.sibling_hashes,
            QUERIES * layout.input_height(),
        )?;
    }
    exact(fri.commit_phase_openings.len(), layout.degree_bits())?;
    for (round, opening) in fri.commit_phase_openings.iter().enumerate() {
        exact(opening.sibling_values.len(), QUERIES)?;
        for values in &opening.sibling_values {
            writer.extensions(values, 1)?;
        }
        exact(opening.opening_proof.0.len(), QUERIES)?;
        for query in &opening.opening_proof.0 {
            exact(query.len(), 1)?;
            writer.fields(&query[0], SALT_ELEMENTS)?;
        }
        writer.siblings(
            &opening.opening_proof.1.sibling_hashes,
            QUERIES * (layout.input_height() - round - 1),
        )?;
    }
    writer.extensions(&fri.final_poly, 1)
}

/// Real proof encoding and hostile input boundary tests.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProofRuntime,
        backend::{
            prover,
            tests::{SquareAir, trace},
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
