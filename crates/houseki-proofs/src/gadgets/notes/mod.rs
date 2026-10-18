//! Shared note validity constraints composed by the individual circuit families.

mod opening;
mod recipient_key;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "complete payment composition follows")
)]
mod spend;

#[cfg(any(test, feature = "prover"))]
pub(crate) use opening::Input as OpeningInput;
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(
    not(test),
    expect(unused_imports, reason = "family assignment handles opening failures")
)]
pub(crate) use opening::OpeningError;
pub(crate) use opening::{CompactOpening, Opening, Selectors as OpeningSelectors};
#[cfg(test)]
pub(crate) use opening::{OpeningAir, OpeningFixture, PaymentOpeningAir};
#[cfg(test)]
pub(crate) use recipient_key::RecipientPairAir;
pub(crate) use recipient_key::eval_pair as eval_recipient_pair;
#[cfg(any(test, feature = "prover"))]
pub(crate) use recipient_key::{RecipientKeyError, assign_pair as assign_recipient_pair};
#[cfg(feature = "prover")]
pub(crate) use spend::Input as SpendInput;
pub(crate) use spend::{Endpoints as SpendEndpoints, Spend};
