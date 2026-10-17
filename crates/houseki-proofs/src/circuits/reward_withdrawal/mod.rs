//! One ordinary output containing exactly the withdrawal body's positive public amount.

mod air;
#[cfg(all(test, feature = "prover"))]
mod fixture;
#[cfg(feature = "prover")]
mod trace;

#[cfg_attr(
    not(feature = "prover"),
    expect(unused_imports, reason = "verifier facade follows")
)]
pub(crate) use air::WithdrawalAir;
