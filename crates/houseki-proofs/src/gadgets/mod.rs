//! Shared constraints and assignment helpers composed by individual circuit families.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "circuit amount consumers follow in later increments"
    )
)]
mod amount;
mod encoding;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "circuit hash consumers follow in later increments"
    )
)]
mod poseidon2;

#[cfg(test)]
pub(crate) use amount::{AdditionAir, AmountAir};
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit trace builders follow in later increments"
    )
)]
pub(crate) use amount::{AmountError, assign_addition, assign_amount};
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit consumers follow in later increments"
    )
)]
pub(crate) use amount::{eval_addition, eval_amount};
#[cfg(test)]
pub(crate) use encoding::{ByteAir, BytesAir, FieldAir};
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit trace builders follow in later increments"
    )
)]
pub(crate) use encoding::{EncodingError, assign_byte, assign_bytes, assign_field_bytes};
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit consumers follow in later increments"
    )
)]
pub(crate) use encoding::{eval_byte, eval_bytes, eval_field_bytes};
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "circuit hash consumers follow in later increments"
    )
)]
pub(crate) use poseidon2::Frame as HashFrame;
#[cfg(test)]
pub(crate) use poseidon2::{FramingAir, PermutationAir};
