//! Complete finite source construction shared only by inline engine tests.

use crate::test_support::{payment_body, trusted_manifest};
use crate::{
    FixtureManifest, FixtureStreamRecord, FixtureUnitId, FixtureUnitRecord, RawOrderUnit,
    SourceCursor, encode_fixture_stream, encode_fixture_unit, validate_bootstrap,
};
use houseki_types::{EncodedTransactionProof, Occurrence, PaymentEnvelope, ValidatorId, VertexId};

/// Constructs an unverified bounded occurrence at a genuine vertex payload slot.
pub(crate) fn fixture_occurrence(index: u64) -> Occurrence {
    Occurrence::new(
        VertexId::from_bytes([1; 64]),
        ValidatorId::from_bytes([5; 64]),
        trusted_manifest().committee_context,
        index,
        PaymentEnvelope::new(
            payment_body(1, 1),
            EncodedTransactionProof::new(vec![1], 1).unwrap(),
        )
        .into(),
    )
}

/// Creates independent fixture trust declarations for a complete finite source.
pub(crate) fn fixture_source(
    units: Vec<Vec<Occurrence>>,
) -> (crate::ParentSnapshot, FixtureManifest, Vec<RawOrderUnit>) {
    fixture_source_for(trusted_manifest(), units)
}

/// Binds complete units to a supplied independently trusted bootstrap fixture.
pub(crate) fn fixture_source_for(
    mut m: crate::BootstrapManifest,
    units: Vec<Vec<Occurrence>>,
) -> (crate::ParentSnapshot, FixtureManifest, Vec<RawOrderUnit>) {
    let mut previous = FixtureUnitId::from_bytes([0; 64]);
    let mut ids = vec![];
    let mut raw = vec![];
    for (ordinal, occurrences) in units.into_iter().enumerate() {
        let bytes = encode_fixture_unit(&FixtureUnitRecord {
            ordinal: ordinal as u64,
            previous_unit_id: previous,
            occurrences,
        })
        .unwrap();
        previous =
            FixtureUnitId::from_bytes(houseki_crypto::ledger_fixture_order_unit(&bytes).unwrap());
        ids.push(previous);
        raw.push(RawOrderUnit::new(bytes));
    }
    let stream = crate::FixtureStreamId::from_bytes(
        houseki_crypto::ledger_fixture_order_stream(
            &encode_fixture_stream(&FixtureStreamRecord {
                network: m.network,
                starting_artifact_id: m.parent_artifact_id,
                unit_ids: ids.clone(),
            })
            .unwrap(),
        )
        .unwrap(),
    );
    m.fixture_unit_ids = ids.clone();
    m.source_cursor = if ids.is_empty() {
        SourceCursor::Exhausted { stream_id: stream }
    } else {
        SourceCursor::Unit {
            stream_id: stream,
            ordinal: 0,
            unit_id: ids[0],
            offset: 0,
        }
    };
    let parent = validate_bootstrap(m.clone()).unwrap().into_snapshot();
    let fixture = FixtureManifest::new(m.network, m.parent_artifact_id, raw.clone());
    (parent, fixture, raw)
}
