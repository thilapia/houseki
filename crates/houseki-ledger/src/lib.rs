//! Deterministic native ledger execution under explicit fixture trust.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod artifact;
mod order;
mod policy;
#[cfg(all(test, feature = "experimental-profiles"))]
mod test_support;

pub use artifact::{
    ArtifactError, ExecutionArtifactId, ExecutionPolicyId, FixtureStreamId, FixtureUnitId,
    StateCommitment,
};
pub use order::{OrderError, SourceCursor};
pub use policy::{ExecutionLimits, ExecutionPolicy, PolicyError};
