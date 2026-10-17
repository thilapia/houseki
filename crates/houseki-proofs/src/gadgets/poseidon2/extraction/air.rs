//! Flat extraction fixture for independent constraint mutation tests.

use super::{assign, eval};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Binds eleven input samples to sixty four digest bytes in one synthetic row.
pub(super) struct ExtractionAir;

impl ExtractionAir {
    /// Assigns all extraction cells without sharing the constraint evaluator's arithmetic.
    pub(super) fn assign_row(values: &[Goldilocks; 11], row: &mut [Goldilocks]) {
        row[..11].copy_from_slice(values);
        let (encodings, rest) = row[11..].split_at_mut(814);
        let (digest, rest) = rest.split_at_mut(64);
        let (bits, carries) = rest.split_at_mut(512);
        assign(
            values,
            encodings.as_chunks_mut::<74>().0.try_into().unwrap(),
            digest.try_into().unwrap(),
            bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            carries.as_chunks_mut::<15>().0.try_into().unwrap(),
        );
    }
}

impl BaseAir<Goldilocks> for ExtractionAir {
    /// Stores canonical sample encodings, output bytes and all signed carry bits.
    fn width(&self) -> usize {
        1641
    }

    /// Keeps the flat mutation fixture within one row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Canonical byte constraints and Boolean carry bits are quadratic.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Exposes independent samples and digest bytes only in this test fixture.
    fn num_public_values(&self) -> usize {
        75
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for ExtractionAir {
    /// Composes the complete extraction relation with public endpoint links.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        eval(
            builder,
            row[..11].try_into().unwrap(),
            row[11..825].as_chunks::<74>().0.try_into().unwrap(),
            row[825..889].try_into().unwrap(),
            row[889..1401].as_chunks::<8>().0.try_into().unwrap(),
            row[1401..].as_chunks::<15>().0.try_into().unwrap(),
        );

        for (index, cell) in row[..11].iter().chain(&row[825..889]).enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*cell, expected);
        }
    }
}
