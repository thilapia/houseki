//! Two pass decoding that validates all canonical bytes before allocating.

use super::{CodecError, HEADER_BYTES, Layout, reader::Reader, writer::exact};
use crate::{
    backend::config::{BackendProof, EXTENSION_DEGREE, QUERIES, SALT_ELEMENTS},
    profile::{ExpectedIdentity, MAX_PROOF_BYTES},
};
use p3_field::PrimeCharacteristicRing;
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::PrunedMerklePaths;
use p3_uni_stark::{Commitments, OpenedValues};

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
pub(super) fn decode_pass(
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
