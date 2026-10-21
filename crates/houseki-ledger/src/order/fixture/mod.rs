//! Finite complete unit fixture authentication under an independent expected stream.

mod manifest;
mod metadata;

pub use manifest::FixtureManifest;

use crate::{
    DecodeLimits, FixtureStreamId, OrderError, ParentSnapshot, RawOrderUnit, VerifiedOrderUnit,
    decode_fixture_unit, encode_occurrences,
};
use metadata::UnitMetadata;

/// Finite source verifier retaining complete source commitments and bounded provenance
/// metadata.
pub struct FixtureOrderVerifier {
    /// Stream identity matched against independently expected parent progress.
    stream: FixtureStreamId,

    /// Exact complete unit identities and predecessor chain.
    units: Vec<UnitMetadata>,

    /// Full expected finite identities, including unconsumed future units.
    complete_ids: std::sync::Arc<[crate::FixtureUnitId]>,
}

impl FixtureOrderVerifier {
    /// Validates all complete fixture declarations before issuing any order capability.
    pub fn new(manifest: FixtureManifest, parent: &ParentSnapshot) -> Result<Self, OrderError> {
        let (stream, units) = manifest.inspect(parent)?;
        let complete_ids = units.iter().map(|u| u.identity).collect::<Vec<_>>().into();
        Ok(Self {
            stream,
            units,
            complete_ids,
        })
    }

    /// Revalidates all retained prefix payloads against independently expected finite
    /// source IDs.
    pub(crate) fn from_replay(
        parent: &ParentSnapshot,
        units: &[std::sync::Arc<[u8]>],
    ) -> Result<Self, OrderError> {
        let archive = parent.archive();
        let raw = units
            .iter()
            .cloned()
            .map(RawOrderUnit::from_shared)
            .collect();
        let manifest =
            FixtureManifest::new(parent.state().network(), archive.starting_artifact, raw);
        let (stream, metadata) =
            manifest.inspect_with_ids(parent, Some(parent.source_unit_ids()))?;
        Ok(Self {
            stream,
            units: metadata,
            complete_ids: std::sync::Arc::from(parent.source_unit_ids()),
        })
    }

    /// Matches complete canonical bytes against the previously authenticated manifest
    /// unit.
    ///
    /// Any unit declared by this manifest may be verified in advance, including a later
    /// unit while the parent cursor still names an earlier one.
    ///
    /// [`crate::LedgerEngine::prepare_next`] enforces exact cursor continuity when
    /// selecting an execution range.
    ///
    /// This operation checks bytes and provenance without establishing transaction
    /// eligibility.
    ///
    /// # Errors
    ///
    /// Rejects an oversized or malformed unit before comparing its ordinal,
    /// predecessor, occurrence count and complete commitment with the retained manifest
    /// metadata.
    ///
    /// Preserves allocation, codec and hashing failures without issuing a capability.
    pub fn verify_unit(&self, raw: RawOrderUnit) -> Result<VerifiedOrderUnit, OrderError> {
        if raw.bytes().len() > 33_554_432 + 72 {
            return Err(OrderError::Bound);
        }

        let decoded = decode_fixture_unit(raw.bytes(), DecodeLimits::reference())?;
        let index = usize::try_from(decoded.ordinal).map_err(|_| OrderError::Bound)?;
        let metadata = self.units.get(index).ok_or(OrderError::Binding)?;
        let identity = crate::FixtureUnitId::from_bytes(houseki_crypto::ledger_fixture_order_unit(
            raw.bytes(),
        )?);
        if metadata.identity != identity
            || metadata.previous != decoded.previous_unit_id
            || metadata.count != decoded.occurrences.len() as u64
        {
            return Err(OrderError::Binding);
        }

        let mut record_lengths = Vec::new();
        record_lengths
            .try_reserve_exact(decoded.occurrences.len())
            .map_err(|_| OrderError::Allocation)?;
        for occurrence in &decoded.occurrences {
            record_lengths.push(
                u64::try_from(encode_occurrences(std::slice::from_ref(occurrence))?.len() - 16)
                    .map_err(|_| OrderError::Bound)?,
            );
        }

        Ok(VerifiedOrderUnit {
            stream_id: self.stream,
            unit_id: identity,
            previous: metadata.previous,
            ordinal: decoded.ordinal,
            successor: self.complete_ids.get(index + 1).copied(),
            occurrences: decoded.occurrences.into(),
            record_lengths,
            canonical: raw.into_shared(),
        })
    }
}

/// Complete source trust and genuine occurrence tests.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::test_support::{fixture_source_for, payment_body, trusted_manifest};
    use crate::{FixtureManifest, RawOrderUnit};
    use houseki_types::{
        EncodedTransactionProof, Occurrence, PaymentEnvelope, ValidatorId, VertexId,
    };

    /// Binds the finite chain to its independently expected network and starting
    /// checkpoint.
    #[test]
    fn manifest_binds_network_start_and_unit_chain() {
        let (parent, fixture, raw) = source(vec![vec![occurrence(0)], vec![]]);
        fixture.validate(&parent).unwrap();
        let verifier = FixtureOrderVerifier::new(fixture, &parent).unwrap();

        assert_eq!(verifier.verify_unit(raw[1].clone()).unwrap().ordinal(), 1);

        let bad = FixtureManifest::new(
            houseki_types::NetworkId::from_bytes([8; 64]),
            parent.head().artifact_id(),
            raw,
        );

        assert!(bad.validate(&parent).is_err());

        let (parent, fixture, _) = source(vec![]);
        fixture.validate(&parent).unwrap();
        let (parent, fixture, _) = source(vec![vec![]; 64]);
        fixture.validate(&parent).unwrap();
        let (_, _, raw) = source(vec![vec![]; 64]);
        let mut too_many = raw;
        too_many.push(too_many[0].clone());

        assert!(
            FixtureManifest::new(
                parent.state().network(),
                parent.head().artifact_id(),
                too_many
            )
            .validate(&parent)
            .is_err()
        );
    }

    /// Preserves identical bodies at separate genuine origin positions.
    #[test]
    fn unit_preserves_genuine_transaction_copies() {
        let (parent, fixture, raw) = source(vec![vec![occurrence(0), occurrence(1)]]);

        let unit = FixtureOrderVerifier::new(fixture, &parent)
            .unwrap()
            .verify_unit(raw[0].clone())
            .unwrap();

        assert_eq!(unit.occurrences().len(), 2);
        assert_eq!(
            unit.occurrences()[0].envelope(),
            unit.occurrences()[1].envelope()
        );
    }

    /// Duplicate origins and contradictory/foreign author declarations fail whole
    /// source trust.
    #[test]
    fn stream_rejects_duplicate_origin_and_foreign_author() {
        let (parent, fixture, _) = source(vec![vec![occurrence(0)], vec![occurrence(0)]]);

        assert!(fixture.validate(&parent).is_err());

        let mut wrong = occurrence(0);
        let (v, _, c, i, e) = wrong.into_parts();
        wrong = Occurrence::new(v, ValidatorId::from_bytes([99; 64]), c, i, e);
        let (parent, fixture, _) = source(vec![vec![wrong]]);

        assert!(fixture.validate(&parent).is_err());

        let (parent, fixture, _) = source(vec![vec![occurrence(1)]]);

        assert!(fixture.validate(&parent).is_err());
    }

    /// Fragmenting or coalescing delivery never changes original authenticated units or
    /// their cuts.
    #[test]
    fn canonical_units_ignore_delivery_callback_grouping() {
        let (parent, fixture, raw) = source(vec![vec![occurrence(0), occurrence(1)], vec![]]);
        let verifier = FixtureOrderVerifier::new(fixture, &parent).unwrap();
        let lengths: Vec<_> = raw.iter().map(|r| r.bytes().len()).collect();
        let wire: Vec<_> = raw.iter().flat_map(|r| r.bytes().iter().copied()).collect();
        let mut expected = None;

        for chunk in [1, 17, wire.len()] {
            let mut buffer = Vec::new();
            let mut next = 0;
            let mut cursor = parent.head().source_cursor().clone();
            let mut cuts = vec![];

            for fragment in wire.chunks(chunk) {
                buffer.extend_from_slice(fragment);

                while next < lengths.len() && buffer.len() >= lengths[next] {
                    let bytes = buffer.drain(..lengths[next]).collect();

                    let unit = verifier.verify_unit(RawOrderUnit::new(bytes)).unwrap();
                    let range =
                        crate::order::next_range(&cursor, &unit, parent.state().policy()).unwrap();
                    cursor = range.next_cursor.clone();
                    cuts.push((unit.unit_id(), range.binding, range.next_cursor));
                    next += 1;
                }
            }

            assert_eq!(next, 2);
            assert!(buffer.is_empty());

            if let Some(expected) = &expected {
                assert_eq!(&cuts, expected)
            } else {
                expected = Some(cuts)
            }
        }

        let truncated = RawOrderUnit::new(raw[0].bytes()[..raw[0].bytes().len() - 1].to_vec());

        assert!(verifier.verify_unit(truncated).is_err());
    }

    /// Truncated or changed complete payload bytes cannot produce a verified unit
    /// capability.
    #[test]
    fn partial_payload_never_verifies() {
        let (parent, fixture, raw) = source(vec![vec![occurrence(0)]]);
        let verifier = FixtureOrderVerifier::new(fixture, &parent).unwrap();
        for length in [0, 7, 71, raw[0].bytes().len() - 1] {
            assert!(
                verifier
                    .verify_unit(RawOrderUnit::new(raw[0].bytes()[..length].to_vec()))
                    .is_err()
            );
        }

        let mut altered = raw[0].bytes().to_vec();
        let n = altered.len();
        altered[n - 9] ^= 1;

        assert!(verifier.verify_unit(RawOrderUnit::new(altered)).is_err());
    }

    /// Constructs an unverified bounded occurrence at a genuine vertex payload slot.
    fn occurrence(index: u64) -> Occurrence {
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
    fn source(
        units: Vec<Vec<Occurrence>>,
    ) -> (crate::ParentSnapshot, FixtureManifest, Vec<RawOrderUnit>) {
        fixture_source_for(trusted_manifest(), units)
    }
}
