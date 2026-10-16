//! Shared values reported by deterministic ledger execution.

mod outcome;
mod rejection_reason;

pub use outcome::ExecutionOutcome;
pub use rejection_reason::ExecutionRejectionReason;
