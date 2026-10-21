//! Bounded public replay archive and separate native historical ownership.

use super::{ExpectedCheckpoint, NativeCheckpoint};
use crate::{
    AnchorRecord, ArtifactError, DecodeLimits, ExecutionArtifactId, FixtureStreamId, FixtureUnitId,
    ReplayInputs, SnapshotRecord, StateCommitment, state::CommittedRecord,
};
use houseki_types::NetworkId;
use std::sync::Arc;

/// Public replay representations that require fresh order and cryptographic verification.
///
/// Decoding never installs its reported state or mints authorization.
#[derive(Clone)]
pub struct ReplayArchive {
    /// Network independently selected at bootstrap.
    pub(crate) network: NetworkId,

    /// Original trusted fixture starting artifact identity.
    pub(crate) starting_artifact: ExecutionArtifactId,

    /// Original independently expected logical state commitment.
    pub(crate) starting_state: StateCommitment,

    /// Independently expected complete finite stream identity.
    pub(crate) stream_id: FixtureStreamId,

    /// Complete finite unit identity list bound by the expected stream.
    pub(crate) unit_ids: Arc<[FixtureUnitId]>,

    /// Complete source payloads for the archived prefix, shared across its slices.
    pub(crate) units: Vec<Arc<[u8]>>,

    /// Actual historical descriptors preserved independently of canonical pruning.
    pub(crate) anchors: Vec<AnchorRecord>,

    /// Complete expected checkpoint records in committed sequence order.
    pub(crate) expected: Vec<Arc<ExpectedCheckpoint>>,

    /// Actual private record ownership, absent for decoded untrusted representations.
    pub(crate) native: Vec<NativeCheckpoint>,
}

impl ReplayArchive {
    /// Creates an empty native archive from an already validated bootstrap record.
    pub(crate) fn bootstrap(record: &Arc<CommittedRecord>) -> Self {
        let ReplayInputs::Bootstrap(manifest) = &record.replay_inputs else {
            unreachable!("validated bootstrap record")
        };
        Self {
            network: manifest.network,
            starting_artifact: manifest.parent_artifact_id,
            starting_state: manifest.expected_state_commitment,
            stream_id: manifest.source_cursor.stream_id(),
            unit_ids: Arc::from(manifest.fixture_unit_ids.as_slice()),
            units: vec![],
            anchors: manifest.anchors.clone(),
            expected: vec![],
            native: vec![],
        }
    }

    /// Borrows complete finite unit identities without authenticating a decoded archive.
    pub fn unit_ids(&self) -> &[FixtureUnitId] {
        &self.unit_ids
    }

    /// Iterates retained complete public unit bytes in ordinal order.
    pub fn source_units(&self) -> impl Iterator<Item = &[u8]> {
        self.units.iter().map(AsRef::as_ref)
    }

    /// Returns the number of reported checkpoint comparison targets.
    pub fn checkpoint_count(&self) -> usize {
        self.expected.len()
    }

    /// Returns the number of retained complete source payloads.
    pub fn source_unit_count(&self) -> usize {
        self.units.len()
    }

    /// Encodes the exact bounded schema-1 public replay container.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        crate::artifact::encode_archive(self)
    }

    /// Decodes representations only and requires independent replay before trust.
    pub fn from_bytes(bytes: &[u8], limits: DecodeLimits) -> Result<Self, ArtifactError> {
        crate::artifact::decode_archive(bytes, limits)
    }

    /// Revalidates retained complete unit bytes against this trusted parent's finite source binding.
    pub fn verify_unit(
        &self,
        parent: &crate::ParentSnapshot,
        ordinal: u64,
    ) -> Result<crate::VerifiedOrderUnit, crate::OrderError> {
        if self.network != parent.state().network()
            || self.starting_artifact != parent.archive().starting_artifact
            || self.starting_state != parent.archive().starting_state
            || self.stream_id != parent.head().source_cursor().stream_id()
            || self.unit_ids.as_ref() != parent.source_unit_ids()
        {
            return Err(crate::OrderError::Binding);
        }
        let index = usize::try_from(ordinal).map_err(|_| crate::OrderError::Bound)?;
        let verifier = crate::FixtureOrderVerifier::from_replay(parent, &self.units)?;
        verifier.verify_unit(crate::RawOrderUnit::from_shared(Arc::clone(
            self.units.get(index).ok_or(crate::OrderError::Binding)?,
        )))
    }
}

/// Reserves complete bounded collection capacity before cloning owned public elements.
pub(crate) fn clone_slice<T: Clone>(values: &[T]) -> Result<Vec<T>, ArtifactError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(values.len())
        .map_err(|_| ArtifactError::Allocation)?;
    output.extend_from_slice(values);
    Ok(output)
}
