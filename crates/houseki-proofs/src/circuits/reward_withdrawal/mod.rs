//! One ordinary output containing exactly the withdrawal body's positive public amount.

mod air;

#[expect(
    unused_imports,
    reason = "family facade consumes the AIR in the next increment"
)]
pub(crate) use air::WithdrawalAir;
