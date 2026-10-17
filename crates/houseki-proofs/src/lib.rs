//! Shared proof infrastructure with explicit profile recognition and bounded execution.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

#[cfg_attr(not(test), allow(dead_code))]
mod backend;
mod context;
#[cfg_attr(not(test), allow(dead_code))]
mod profile;
mod runtime;
#[cfg_attr(not(test), allow(dead_code))]
mod statement;

pub use context::{ContextError, ProofContext};
pub use runtime::{ProofRuntime, RuntimeError};

pub use statement::StatementError;
