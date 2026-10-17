//! Shared note validity constraints composed by the individual circuit families.

mod recipient_key;

#[cfg(test)]
pub(crate) use recipient_key::RecipientPairAir;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit note consumers follow in later increments"
    )
)]
pub(crate) use recipient_key::eval_pair as eval_recipient_pair;
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit note consumers follow in later increments"
    )
)]
pub(crate) use recipient_key::{RecipientKeyError, assign_pair as assign_recipient_pair};
