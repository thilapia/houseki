//! Deterministic native ledger execution under explicit fixture trust.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod artifact;
mod bootstrap;
mod eligibility;
mod engine;
mod execution;
mod order;
mod policy;
mod state;
mod store;
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
pub use bootstrap::{ValidatedBootstrap, validate_bootstrap};
pub use eligibility::{AuthorizedUnit, UnitPreparationError};
pub use engine::LedgerEngine;
pub use execution::ExecutionError;
pub use order::{
    FixtureManifest, FixtureOrderVerifier, OrderError, RawOrderUnit, SourceCursor,
    VerifiedOrderUnit,
};
pub use policy::CheckpointRules;
pub use policy::{ExecutionLimits, ExecutionPolicy, PolicyError};
pub use state::{AnchorRecord, LogicalState, StateError, WorkingState};
pub use state::{HeadRecord, ParentSnapshot, ParentToken, ReplayInputs};
pub use store::ReplayArchive;
