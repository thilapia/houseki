//! Shared constraints and assignment helpers composed by individual circuit families.

mod encoding;

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
