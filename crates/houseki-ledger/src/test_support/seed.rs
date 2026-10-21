//! Complete real signed withdrawal seed with only public trusted inputs.

use crate::{
    BootstrapManifest, DecodeLimits, ExecutionArtifactId, FixtureStreamId, FixtureUnitId,
    SourceCursor, StateCommitment, decode_fixture_unit, decode_snapshot,
};
use houseki_types::{CheckpointSequence, Occurrence};
use std::{fs, path::PathBuf};

/// Loads public fixture files relative to this crate in native unit tests.
fn bytes(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/reference-v1/real/seed-unit")
            .join(name),
    )
    .unwrap()
}

/// Decodes one complete fixed-width public fixture digest.
fn digest(name: &str) -> [u8; 64] {
    let text = String::from_utf8(bytes(name)).unwrap();
    std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}

/// Reconstructs independently retained public bootstrap declarations and the real seed occurrence.
pub(crate) fn seed_fixture() -> (BootstrapManifest, Occurrence) {
    let record = decode_snapshot(&bytes("bootstrap-state.bin"), DecodeLimits::reference()).unwrap();
    let raw = bytes("unit.bin");
    let unit = decode_fixture_unit(&raw, DecodeLimits::reference()).unwrap();
    let manifest = BootstrapManifest {
        network: record.network,
        sequence: CheckpointSequence::new(0),
        parent_artifact_id: ExecutionArtifactId::from_bytes([0; 64]),
        expected_state_commitment: StateCommitment::from_bytes(digest("bootstrap-state.hex")),
        expected_note_anchor: record.note_anchor,
        fixture_unit_ids: vec![FixtureUnitId::from_bytes(
            houseki_crypto::ledger_fixture_order_unit(&raw).unwrap(),
        )],
        source_cursor: SourceCursor::Unit {
            stream_id: FixtureStreamId::from_bytes(digest("stream.hex")),
            ordinal: 0,
            unit_id: FixtureUnitId::from_bytes(
                houseki_crypto::ledger_fixture_order_unit(&raw).unwrap(),
            ),
            offset: 0,
        },
        leaves: vec![],
        spent: record.spent,
        accounts: record.accounts,
        anchors: record.anchors,
        policy: record.policy,
        committee_context: record.committee_context,
        committee: record.committee,
        pool: record.pool,
        issued: record.issued,
    };
    (manifest, unit.occurrences[0].clone())
}
