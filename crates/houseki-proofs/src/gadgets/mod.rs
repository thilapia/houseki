//! Shared constraints and assignment helpers composed by individual circuit families.

mod encoding;

#[cfg(test)]
pub(crate) use encoding::ByteAir;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit consumers follow in later increments"
    )
)]
pub(crate) use encoding::eval_byte;
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit trace builders follow in later increments"
    )
)]
pub(crate) use encoding::{EncodingError, assign_byte};
