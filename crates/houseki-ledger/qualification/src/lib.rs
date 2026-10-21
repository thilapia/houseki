//! Independent verifier-only consumer and explicitly enabled public fixture production.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod checkpoint_measurement;
mod consumer;
mod error;
mod workload;
pub use consumer::{VerificationSummary, verify};
pub use error::QualificationError;
pub use workload::Workload;

#[cfg(feature = "prover")]
mod owner;
#[cfg(feature = "prover")]
mod payment_fixture;
#[cfg(feature = "prover")]
mod producer;
#[cfg(feature = "prover")]
mod wallet;
#[cfg(feature = "prover")]
pub use producer::seed;

/// Installs protected private allocation only in the explicitly proving test process.
#[cfg(all(test, feature = "prover"))]
#[global_allocator]
static TEST_ALLOCATOR: houseki_proofs::ProofAllocator<std::alloc::System> =
    houseki_proofs::ProofAllocator::new(std::alloc::System);
