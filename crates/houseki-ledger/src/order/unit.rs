//! Owned complete fixture order evidence with private validated construction.

use crate::{FixtureStreamId, FixtureUnitId};
use houseki_types::Occurrence;
use std::sync::Arc;

/// Complete bounded order capability issued only by the fixture verifier.
///
/// This capability establishes fixture order and leaves every proof/signature check pending.
#[derive(Debug)]
pub struct VerifiedOrderUnit {
    /// Exact finite source identity checked against the trusted parent cursor.
    pub(crate) stream_id: FixtureStreamId,

    /// Complete canonical unit commitment.
    pub(crate) unit_id: FixtureUnitId,

    /// Previous manifest-authenticated unit identity.
    pub(crate) previous: FixtureUnitId,

    /// Exact source unit ordinal.
    pub(crate) ordinal: u64,

    /// Authenticated next unit identity or exhausted source.
    pub(crate) successor: Option<FixtureUnitId>,

    /// Every original occurrence in canonical unit order.
    pub(crate) occurrences: Arc<[Occurrence]>,

    /// Complete occurrence record lengths, excluding the surrounding list prefixes.
    pub(crate) record_lengths: Vec<u64>,

    /// Original complete canonical bytes retained for authorization and replay.
    pub(crate) canonical: Arc<[u8]>,
}

impl VerifiedOrderUnit {
    /// Returns the zero based source unit ordinal.
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Returns the complete source unit identity.
    pub const fn unit_id(&self) -> FixtureUnitId {
        self.unit_id
    }

    /// Returns the exact finite stream identity.
    pub const fn stream_id(&self) -> FixtureStreamId {
        self.stream_id
    }

    /// Returns the manifest-authenticated predecessor identity.
    pub const fn previous_unit_id(&self) -> FixtureUnitId {
        self.previous
    }

    /// Returns the manifest-authenticated successor, if any.
    pub const fn successor(&self) -> Option<FixtureUnitId> {
        self.successor
    }

    /// Borrows every complete ordered occurrence without mutable access.
    pub fn occurrences(&self) -> &[Occurrence] {
        &self.occurrences
    }

    /// Shares the immutable complete public source bytes across checkpoint slices.
    pub(crate) fn canonical_owner(&self) -> Arc<[u8]> {
        Arc::clone(&self.canonical)
    }

    /// Shares immutable typed inputs without copying proof bytes for each slice.
    pub(crate) fn occurrences_owner(&self) -> Arc<[Occurrence]> {
        Arc::clone(&self.occurrences)
    }

    /// Borrows original complete canonical bytes for local replay.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}
