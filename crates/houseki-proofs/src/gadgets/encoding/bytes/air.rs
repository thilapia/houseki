//! Test relation preserving every byte of a fixed-width public value.

use crate::gadgets::eval_bytes;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Constrains all byte cells and links each position to its expected public byte.
pub(crate) struct BytesAir<const N: usize>;

impl<const N: usize> BaseAir<Goldilocks> for BytesAir<N> {
    /// Stores all values followed by eight bits per value.
    fn width(&self) -> usize {
        9 * N
    }

    /// Evaluates this test relation within the current row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Reserves the quadratic degree of the underlying Boolean constraints.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Exposes every expected byte without reducing an identifier modulo the field.
    fn num_public_values(&self) -> usize {
        N
    }
}

impl<const N: usize, AB: AirBuilder<F = Goldilocks>> Air<AB> for BytesAir<N> {
    /// Applies the shared gadget and a separate public equality at every position.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let values: &[AB::Var; N] = row[..N].try_into().unwrap();
        let bits = row[N..].as_chunks::<8>().0.try_into().unwrap();
        eval_bytes(builder, values, bits);

        for (index, value) in values.iter().enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*value, expected);
        }
    }
}
