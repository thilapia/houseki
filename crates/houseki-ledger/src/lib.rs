//! Deterministic native ledger execution under explicit fixture trust.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod artifact;
mod bootstrap;
mod order;
mod policy;
mod state;
#[cfg(all(test, feature = "experimental-profiles"))]
mod test_support;

pub use artifact::{
    ArtifactError, ExecutionArtifactId, ExecutionPolicyId, FixtureStreamId, FixtureUnitId,
    StateCommitment,
};
pub use bootstrap::{BootstrapCandidate, BootstrapError, BootstrapManifest, CommitteeEntry};
pub use order::{OrderError, SourceCursor};
pub use policy::CheckpointRules;
pub use policy::{ExecutionLimits, ExecutionPolicy, PolicyError};
pub use state::{AnchorRecord, LogicalState, StateError, WorkingState};
