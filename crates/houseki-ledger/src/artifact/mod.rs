//! Canonical public reference identities and representation errors.

mod error;
mod identifier;
pub use error::ArtifactError;
pub use identifier::{
    ExecutionArtifactId, ExecutionPolicyId, FixtureStreamId, FixtureUnitId, StateCommitment,
};
