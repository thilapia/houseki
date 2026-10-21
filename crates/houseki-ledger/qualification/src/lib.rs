//! Independent verifier-only consumer and explicitly enabled public fixture production.

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

mod checkpoint_measurement;
mod consumer;
mod error;
mod workload;
pub use consumer::{VerificationSummary, verify};
pub use error::QualificationError;
pub use workload::Workload;
