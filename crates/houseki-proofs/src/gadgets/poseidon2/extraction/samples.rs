//! Reuse of the canonical field encoding relation for all eleven digest samples.

use super::profile::ENCODING;
#[cfg(any(test, feature = "prover"))]
use crate::gadgets::assign_field_bytes;
use crate::gadgets::eval_field_bytes;
use crate::gadgets::poseidon2::profile::SAMPLES;
use p3_air::AirBuilder;
use p3_goldilocks::Goldilocks;

/// Constrains every sample's eight bytes, bits and canonicality helpers.
pub(in crate::gadgets::poseidon2) fn eval<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    values: &[AB::Var; SAMPLES],
    encodings: &[[AB::Var; ENCODING]; SAMPLES],
) {
    for (value, row) in values.iter().zip(encodings) {
        eval_field_bytes(
            builder,
            *value,
            row[..8].try_into().unwrap(),
            row[8..72].as_chunks::<8>().0.try_into().unwrap(),
            row[72],
            row[73],
        );
    }
}

/// Overwrites each borrowed encoding through its existing canonical assignment owner.
#[cfg(any(test, feature = "prover"))]
pub(super) fn assign(
    values: &[Goldilocks; SAMPLES],
    encodings: &mut [[Goldilocks; ENCODING]; SAMPLES],
) {
    for (value, row) in values.iter().zip(encodings) {
        let (bytes, rest) = row.split_at_mut(8);
        let (bits, helpers) = rest.split_at_mut(64);
        let (is_max, inverse) = helpers.split_at_mut(1);
        assign_field_bytes(
            value,
            bytes.try_into().unwrap(),
            bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            &mut is_max[0],
            &mut inverse[0],
        );
    }
}
