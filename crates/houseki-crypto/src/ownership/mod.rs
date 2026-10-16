//! Protected secrets for Houseki ownership relations.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Public ownership consumers are separate increments."
    )
)]
mod commitment;
mod nullifier_key;
mod spending_key;

pub use nullifier_key::{NullifierKey, NullifierKeyError};
pub use spending_key::{SpendingKey, SpendingKeyError};
