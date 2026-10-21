//! Exact schema 1 replay container carrying public representations only.

use super::{DecodeLimits, reader::Reader, records, writer::Writer};
use crate::store::{ExpectedCheckpoint, ReplayArchive};
use crate::{
    ArtifactError, ExecutionArtifactId, FixtureStreamId, FixtureUnitId, SourceCursor,
    StateCommitment, decode_artifact_header, decode_fixture_unit, decode_snapshot,
    encode_artifact_header, encode_effects, encode_receipts, encode_snapshot,
};
use houseki_types::{NetworkId, NoteCommitment};
use std::sync::Arc;

/// Derives the conservative maximum complete encoded archive from exact bounded record
/// widths.
fn maximum_bytes() -> u128 {
    let policy = 244_u128;
    let list = |count: u128, size: u128| 8 + count * (8 + size);
    let snapshot = 144
        + list(4096, 64)
        + list(64, 2680)
        + list(64, 152)
        + (8 + policy)
        + 72
        + list(64, 16536)
        + 32;
    let expected =
        (8 + 828) + list(64, 80) + list(64, 828) + (8 + snapshot) + list(4096, 64) + (8 + 148);
    260 + list(64, 64) + list(64, 33554432 + 72) + list(8256, 152) + list(8192, expected)
}

/// Emits one complete expected record without treating its effects as trusted writes.
fn encode_expected(v: &ExpectedCheckpoint) -> Result<Vec<u8>, ArtifactError> {
    if v.leaves.len() > 4096
        || v.header.occurrence_count as u128 != v.receipts.len() as u128
        || v.receipts.len() != v.effects.len()
        || v.state.note_anchor.count().value() != v.leaves.len() as u128
    {
        return Err(ArtifactError::Invalid);
    }

    let mut w = Writer::new();
    w.blob(&encode_artifact_header(&v.header)?)?;
    w.raw(&encode_receipts(&v.receipts)?)?;
    w.raw(&encode_effects(&v.effects)?)?;
    w.blob(&encode_snapshot(&v.state)?)?;
    w.list(&v.leaves, |n| Ok(n.as_bytes().to_vec()))?;
    w.blob(&v.cursor.to_bytes())?;
    Ok(w.finish())
}

/// Decodes a complete expected record while preserving existing nested record codecs.
fn decode_expected(b: &[u8], l: DecodeLimits) -> Result<ExpectedCheckpoint, ArtifactError> {
    let mut r = Reader::new(b, l)?;
    let header = decode_artifact_header(r.blob()?, l)?;
    let receipts = r.list(64, |b| records::decode_receipt(b, l))?;
    let effects = r.list(64, |b| records::decode_effect(b, l))?;
    let state = decode_snapshot(r.blob()?, l)?;
    let leaves = r.list(4096, |b| {
        let mut r = Reader::new(b, l)?;
        let value = NoteCommitment::from_bytes(r.fixed()?);
        r.finish()?;
        Ok(value)
    })?;

    let cursor = SourceCursor::from_bytes(r.blob()?).map_err(|_| ArtifactError::Invalid)?;
    r.finish()?;
    let value = ExpectedCheckpoint {
        header,
        receipts,
        effects,
        state,
        leaves,
        cursor,
    };

    if encode_expected(&value)? != b {
        return Err(ArtifactError::Invalid);
    }

    Ok(value)
}

/// Encodes the exact replay outer field order under the finite reference caps.
pub(crate) fn encode_archive(v: &ReplayArchive) -> Result<Vec<u8>, ArtifactError> {
    if v.unit_ids.len() > 64
        || v.units.len() > v.unit_ids.len()
        || v.anchors.len() > 8256
        || v.expected.len() > 8192
    {
        return Err(ArtifactError::Bound);
    }

    let mut w = Writer::new();
    w.u32(1)?;
    w.raw(v.network.as_bytes())?;
    w.raw(v.starting_artifact.as_bytes())?;
    w.raw(v.starting_state.as_bytes())?;
    w.raw(v.stream_id.as_bytes())?;
    w.list(&v.unit_ids, |v| Ok(v.as_bytes().to_vec()))?;
    w.list(&v.units, |bytes| {
        if bytes.len() > 33554432 + 72 {
            return Err(ArtifactError::Bound);
        }

        Ok(bytes.to_vec())
    })?;

    w.list(&v.anchors, records::encode_anchor)?;
    w.list(&v.expected, |v| encode_expected(v))?;
    let bytes = w.finish();
    if bytes.len() as u128 > maximum_bytes() {
        return Err(ArtifactError::Bound);
    }

    Ok(bytes)
}

/// Decodes bounded public records without installing expected state or verification
/// evidence.
pub(crate) fn decode_archive(b: &[u8], l: DecodeLimits) -> Result<ReplayArchive, ArtifactError> {
    if b.len() as u128 > maximum_bytes() {
        return Err(ArtifactError::Bound);
    }

    let mut r = Reader::new(b, l)?;
    if r.u32()? != 1 {
        return Err(ArtifactError::Invalid);
    }

    let network = NetworkId::from_bytes(r.fixed()?);
    let starting_artifact = ExecutionArtifactId::from_bytes(r.fixed()?);
    let starting_state = StateCommitment::from_bytes(r.fixed()?);
    let stream_id = FixtureStreamId::from_bytes(r.fixed()?);
    let unit_ids = r.list(64, |b| {
        let mut r = Reader::new(b, l)?;
        let v = FixtureUnitId::from_bytes(r.fixed()?);
        r.finish()?;
        Ok(v)
    })?;

    for (i, id) in unit_ids.iter().enumerate() {
        if unit_ids[..i].contains(id) {
            return Err(ArtifactError::Invalid);
        }
    }

    let units = r.list(64, |b| {
        if b.len() > 33554432 + 72 {
            return Err(ArtifactError::Bound);
        }

        let _decoded = decode_fixture_unit(b, l)?;
        Ok(Arc::from(b))
    })?;

    if units.len() > unit_ids.len() {
        return Err(ArtifactError::Invalid);
    }

    let anchors = r.list(8256, |b| records::decode_anchor(b, l))?;
    let expected = r.list(8192, |b| decode_expected(b, l).map(Arc::new))?;
    r.finish()?;
    Ok(ReplayArchive {
        network,
        starting_artifact,
        starting_state,
        stream_id,
        unit_ids: unit_ids.into(),
        units,
        anchors,
        expected,
        native: vec![],
    })
}
