//! Deterministic native ledger execution under explicit fixture trust.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod artifact;
mod bootstrap;
mod order;
mod policy;
mod state;
#[cfg(all(test, feature = "experimental-profiles"))]
mod test_support;

pub use artifact::ExecutionArtifact;
pub use artifact::{
    AcceptedEffect, AccountEffect, ArtifactError, ArtifactHeader, DecodeLimits, EffectRecord,
    ExecutionArtifactId, ExecutionPolicyId, FixtureStreamId, FixtureStreamRecord, FixtureUnitId,
    FixtureUnitRecord, NoteAppend, OrderBinding, SnapshotRecord, StateCommitment,
    decode_artifact_header, decode_effects, decode_fixture_stream, decode_fixture_unit,
    decode_occurrences, decode_policy, decode_receipts, decode_snapshot, encode_artifact_header,
    encode_effects, encode_fixture_stream, encode_fixture_unit, encode_occurrences, encode_policy,
    encode_receipts, encode_snapshot,
};
pub use bootstrap::{BootstrapCandidate, BootstrapError, BootstrapManifest, CommitteeEntry};
pub use order::{OrderError, SourceCursor};
pub use policy::CheckpointRules;
pub use policy::{ExecutionLimits, ExecutionPolicy, PolicyError};
pub use state::{AnchorRecord, LogicalState, StateError, WorkingState};
