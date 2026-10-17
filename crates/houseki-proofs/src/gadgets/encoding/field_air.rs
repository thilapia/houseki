//! Test relation for canonical scalar bytes with an independently supplied public value.

use crate::gadgets::{assign_field_bytes, eval_field_bytes};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Links the canonical byte representation to the expected scalar in each row.
pub(crate) struct FieldAir;

impl FieldAir {
    /// Writes the public fixture and all encoding cells into an existing test row.
    pub(crate) fn assign_row(value: &Goldilocks, row: &mut [Goldilocks; 75]) {
        let (scalar, encoding) = row.split_at_mut(1);
        scalar[0] = *value;
        let (bytes, encoding) = encoding.split_at_mut(8);
        let (bits, helpers) = encoding.split_at_mut(64);
        let (high_is_max, high_gap_inverse) = helpers.split_at_mut(1);
        assign_field_bytes(
            value,
            bytes.try_into().unwrap(),
            bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            &mut high_is_max[0],
            &mut high_gap_inverse[0],
        );
    }
}

impl BaseAir<Goldilocks> for FieldAir {
    /// Stores the scalar, eight bytes, 64 bits and two canonicality helpers.
    fn width(&self) -> usize {
        75
    }

    /// Evaluates the relation entirely within the current row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Reserves quadratic constraints even during adversarial omission tests.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Exposes the expected scalar independently of its witness encoding.
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for FieldAir {
    /// Applies canonical encoding and binds the scalar to the public statement.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        eval_field_bytes(
            builder,
            row[0],
            row[1..9].try_into().unwrap(),
            row[9..73].as_chunks::<8>().0.try_into().unwrap(),
            row[73],
            row[74],
        );

        let expected = builder.public_values()[0];
        builder.assert_eq(row[0], expected);
    }
}
