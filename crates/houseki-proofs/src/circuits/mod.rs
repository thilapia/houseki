//! Complete transaction relations composed from shared constraints and native statements.

mod error;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "payment admission follows complete qualification")
)]
pub(crate) mod payment;
pub(crate) mod reward_withdrawal;

#[cfg(feature = "prover")]
pub use error::ProveError;
pub use error::{ProofEncodingError, VerifyError};
