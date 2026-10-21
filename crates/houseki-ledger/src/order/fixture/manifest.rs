//! Full finite fixture declarations bound by the independently expected stream identity.

use super::metadata::UnitMetadata;
use crate::{
    DecodeLimits, ExecutionArtifactId, FixtureStreamId, FixtureStreamRecord, FixtureUnitId,
    OrderError, ParentSnapshot, RawOrderUnit, SourceCursor, decode_fixture_unit,
    encode_fixture_stream, encode_occurrences,
};
use houseki_types::{CommitteeContext, NetworkId, ValidatorId};
use std::collections::{HashMap, HashSet};

/// Complete source declarations supplied under explicit fixture trust.
///
/// Validation consumes no cryptographic eligibility assertion and retains only bounded
/// provenance metadata after complete source commitments have been checked.
#[derive(Clone)]
pub struct FixtureManifest {
    /// Network that identifies the finite fixture source.
    network: NetworkId,

    /// Trusted starting checkpoint identity, preserved across descendants.
    starting_artifact: ExecutionArtifactId,

    /// Complete bounded units, validated individually before their payload bytes are
    /// released.
    units: Vec<RawOrderUnit>,
}

impl FixtureManifest {
    /// Retains full source declarations without checking their trust binding.
    pub fn new(
        network: NetworkId,
        starting_artifact: ExecutionArtifactId,
        units: Vec<RawOrderUnit>,
    ) -> Self {
        Self {
            network,
            starting_artifact,
            units,
        }
    }

    /// Validates exact complete source bytes and provenance against the trusted parent.
    ///
    /// Bounds every unit and the complete finite stream under the parent policy, checks
    /// the predecessor chain and expected stream identity, and requires unique origins
    /// with contiguous payload indices from registered authors in the fixed committee.
    ///
    /// Each complete occurrence must fit a checkpoint component budget.
    ///
    /// Successful validation authenticates fixture provenance without checking wallet
    /// proofs.
    ///
    /// # Errors
    ///
    /// Rejects source or progress mismatches, duplicate origins and unsliceable
    /// occurrences, preserving bounded allocation, codec and hashing failures.
    pub fn validate(&self, parent: &ParentSnapshot) -> Result<(), OrderError> {
        self.inspect(parent).map(|_| ())
    }

    /// Computes finite source metadata after checking every source envelope and origin.
    pub(super) fn inspect(
        &self,
        parent: &ParentSnapshot,
    ) -> Result<(FixtureStreamId, Vec<UnitMetadata>), OrderError> {
        self.inspect_with_ids(parent, None)
    }

    /// Validates complete retained prefix payloads against the independently expected
    /// finite list.
    pub(super) fn inspect_with_ids(
        &self,
        parent: &ParentSnapshot,
        complete_ids: Option<&[FixtureUnitId]>,
    ) -> Result<(FixtureStreamId, Vec<UnitMetadata>), OrderError> {
        let policy = parent.state().policy();
        let limits = policy.limits();
        if self.network != parent.state().network()
            || self.units.len() as u128 > u128::from(limits.fixture_units())
        {
            return Err(OrderError::Binding);
        }

        if parent.artifact().is_none() && self.starting_artifact != parent.head().artifact_id() {
            return Err(OrderError::Binding);
        }

        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(self.units.len())
            .map_err(|_| OrderError::Allocation)?;
        let mut origins = HashSet::new();
        let mut vertices: HashMap<[u8; 64], (ValidatorId, CommitteeContext, u64, u64)> =
            HashMap::new();
        let mut previous = FixtureUnitId::from_bytes([0; 64]);
        for (ordinal, raw) in self.units.iter().enumerate() {
            if raw.bytes().len() as u128 > u128::from(limits.unit_bytes()) + 72 {
                return Err(OrderError::Bound);
            }

            let unit = decode_fixture_unit(raw.bytes(), DecodeLimits::reference())?;
            if unit.ordinal != ordinal as u64
                || unit.previous_unit_id != previous
                || unit.occurrences.len() as u128 > u128::from(limits.unit_occurrences())
            {
                return Err(OrderError::Binding);
            }

            let components = encode_occurrences(&unit.occurrences)?;
            if components.len() as u128 > u128::from(limits.unit_bytes()) {
                return Err(OrderError::Bound);
            }

            origins
                .try_reserve(unit.occurrences.len())
                .map_err(|_| OrderError::Allocation)?;
            vertices
                .try_reserve(unit.occurrences.len())
                .map_err(|_| OrderError::Allocation)?;
            for occurrence in &unit.occurrences {
                if occurrence.committee_context() != parent.state().committee_context()
                    || parent
                        .state()
                        .beneficiary(occurrence.vertex_author())
                        .is_none()
                {
                    return Err(OrderError::Binding);
                }

                if occurrence.transaction_index() >= 8192 {
                    return Err(OrderError::Bound);
                }

                let origin = (
                    occurrence.vertex_id().into_bytes(),
                    occurrence.transaction_index(),
                );
                if !origins.insert(origin) {
                    return Err(OrderError::DuplicateOrigin);
                }

                let record = vertices.entry(origin.0).or_insert((
                    occurrence.vertex_author(),
                    occurrence.committee_context(),
                    0,
                    0,
                ));
                if record.0 != occurrence.vertex_author()
                    || record.1 != occurrence.committee_context()
                {
                    return Err(OrderError::Binding);
                }

                if occurrence.transaction_index() != record.2 {
                    return Err(OrderError::Binding);
                }

                record.2 += 1;
                record.3 = record.3.max(occurrence.transaction_index());
                let size = encode_occurrences(std::slice::from_ref(occurrence))?.len() as u128;
                if size > u128::from(limits.batch_bytes()) {
                    return Err(OrderError::UnitInadmissible);
                }
            }

            previous =
                FixtureUnitId::from_bytes(houseki_crypto::ledger_fixture_order_unit(raw.bytes())?);
            metadata.push(UnitMetadata {
                identity: previous,
                previous: unit.previous_unit_id,
                count: unit.occurrences.len() as u64,
            });
        }

        if vertices.values().any(|v| v.3 + 1 != v.2) {
            return Err(OrderError::Binding);
        }

        let known_ids: Vec<_> = metadata.iter().map(|v| v.identity).collect();
        let ids = if let Some(complete) = complete_ids {
            if complete.len() > 64
                || known_ids.len() > complete.len()
                || complete[..known_ids.len()] != known_ids
            {
                return Err(OrderError::Binding);
            }

            complete.to_vec()
        } else {
            known_ids
        };

        let stream = FixtureStreamId::from_bytes(houseki_crypto::ledger_fixture_order_stream(
            &encode_fixture_stream(&FixtureStreamRecord {
                network: self.network,
                starting_artifact_id: self.starting_artifact,
                unit_ids: ids,
            })?,
        )?);
        match parent.head().source_cursor() {
            SourceCursor::Exhausted { stream_id } => {
                if *stream_id != stream || (parent.artifact().is_none() && !metadata.is_empty()) {
                    return Err(OrderError::Binding);
                }
            }
            SourceCursor::Unit {
                stream_id,
                ordinal,
                unit_id,
                offset,
            } => {
                let index = usize::try_from(*ordinal).map_err(|_| OrderError::Bound)?;
                let current = metadata.get(index).ok_or(OrderError::Binding)?;
                if *stream_id != stream
                    || *unit_id != current.identity
                    || (*offset >= current.count && !(current.count == 0 && *offset == 0))
                {
                    return Err(OrderError::Binding);
                }
            }
        }

        Ok((stream, metadata))
    }
}
