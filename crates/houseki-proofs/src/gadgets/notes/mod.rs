//! Shared note validity constraints composed by the individual circuit families.

mod opening;
mod recipient_key;

#[cfg(any(test, feature = "prover"))]
pub(crate) use opening::Input as OpeningInput;
#[cfg_attr(
    not(test),
    expect(unused_imports, reason = "family AIR composition follows")
)]
pub(crate) use opening::Opening;
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(
    not(test),
    expect(unused_imports, reason = "family assignment handles opening failures")
)]
pub(crate) use opening::OpeningError;
#[cfg(test)]
pub(crate) use opening::{OpeningAir, OpeningFixture};
#[cfg(test)]
pub(crate) use recipient_key::RecipientPairAir;
pub(crate) use recipient_key::eval_pair as eval_recipient_pair;
#[cfg(any(test, feature = "prover"))]
pub(crate) use recipient_key::{RecipientKeyError, assign_pair as assign_recipient_pair};
