//! Complete transaction relations composed from shared constraints and native statements.

mod error;
pub(crate) mod payment;
pub(crate) mod reward_withdrawal;

#[cfg(feature = "prover")]
pub use error::ProveError;
pub use error::{ProofEncodingError, VerifyError};
