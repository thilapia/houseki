//! Independent verifier-only consumer and explicitly enabled public fixture production.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod checkpoint_measurement;
mod consumer;
mod error;
#[cfg(feature = "prover")]
mod execution;
#[cfg(feature = "prover")]
mod loop_fixture;
#[cfg(feature = "prover")]
mod measurement;
#[cfg(feature = "prover")]
mod owner;
#[cfg(feature = "prover")]
mod payment_fixture;
#[cfg(feature = "prover")]
mod producer;
#[cfg(feature = "prover")]
mod public_fixture;
#[cfg(feature = "prover")]
mod wallet;
mod workload;

pub use consumer::{VerificationSummary, verify};
pub use error::QualificationError;
#[cfg(feature = "prover")]
pub use measurement::Measurement;
#[cfg(feature = "prover")]
pub use producer::{generate, seed};
#[cfg(feature = "prover")]
pub use public_fixture::PublicFixture;
pub use workload::Workload;

/// Installs protected private allocation only in the explicitly proving test process.
#[cfg(all(test, feature = "prover"))]
#[global_allocator]
static TEST_ALLOCATOR: houseki_proofs::ProofAllocator<std::alloc::System> =
    houseki_proofs::ProofAllocator::new(std::alloc::System);
