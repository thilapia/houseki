//! Shared proof infrastructure with explicit profile recognition and bounded execution.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

#[cfg_attr(not(test), allow(dead_code))]
mod backend;
#[cfg(any(test, feature = "prover"))]
mod cancellation;
#[cfg_attr(not(test), allow(dead_code))]
mod circuits;
mod context;
mod gadgets;
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(not(test), allow(dead_code))]
mod memory;
#[cfg(feature = "prover")]
mod payment;
#[cfg_attr(not(test), allow(dead_code))]
mod profile;
mod runtime;
#[cfg_attr(not(test), allow(dead_code))]
mod statement;
#[cfg(test)]
mod test_allocator;

#[cfg(any(test, feature = "prover"))]
pub use cancellation::CancellationToken;
pub use context::{ContextError, ProofContext};
#[cfg(feature = "prover")]
pub use memory::ProofAllocator;
#[cfg(feature = "prover")]
pub use payment::{PaymentWitness, WitnessShapeError};
pub use runtime::{ProofRuntime, RuntimeError};
pub use statement::StatementError;
