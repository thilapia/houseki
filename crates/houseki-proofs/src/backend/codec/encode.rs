//! Canonical proof encoding with a complete validation and sizing pass.

use houseki_types::EncodedTransactionProof;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use super::{
    CodecError, HEADER_BYTES, Layout,
    writer::{Writer, exact},
};
use crate::{
    backend::config::{BackendProof, EXTENSION_DEGREE, QUERIES, SALT_ELEMENTS},
    profile::{ExpectedIdentity, MAX_PROOF_BYTES},
};

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
