//! External public consumers and device qualification for the experimental proof candidate.

mod error;
#[cfg(feature = "prover")]
#[path = "../../examples/payment/owner.rs"]
#[allow(
    dead_code,
    reason = "The shared owner also supports delivery recovery outside the measured proof boundary."
)]
mod owner;
#[cfg(feature = "prover")]
#[path = "../../examples/payment/fixture.rs"]
#[allow(
    dead_code,
    reason = "The shared fixture also supports delivery and respend outside this measurement."
)]
mod payment_fixture;
#[cfg(feature = "prover")]
mod producer;
mod public_artifact;
mod sample;
#[cfg(feature = "prover")]
#[path = "../../examples/reward_withdrawal/fixture.rs"]
#[allow(
    dead_code,
    reason = "The shared fixture retains delivery and signing owners outside the output proof claim."
)]
mod withdrawal_fixture;
mod workload;

pub use error::Error;
#[cfg(feature = "prover")]
pub use producer::produce;
pub use public_artifact::PublicArtifact;
pub use sample::Sample;
pub use workload::Workload;

/// Installs the public allocator contract for every producer executable and mobile shell.
#[cfg(feature = "prover")]
#[global_allocator]
static ALLOCATOR: houseki_proofs::ProofAllocator<std::alloc::System> =
    houseki_proofs::ProofAllocator::new(std::alloc::System);
