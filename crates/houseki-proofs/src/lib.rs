//! Shared proof infrastructure with explicit profile recognition and bounded execution.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod context;
mod runtime;

pub use context::{ContextError, ProofContext};
pub use runtime::{ProofRuntime, RuntimeError};
