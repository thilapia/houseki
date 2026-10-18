//! Test relation for a byte linked to an expected public value.

use crate::gadgets::eval_byte;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Exercises byte constraints without admitting a production circuit or profile.
pub(crate) struct ByteAir;

impl BaseAir<Goldilocks> for ByteAir {
    /// Stores one value and eight auxiliary bits per row.
    fn width(&self) -> usize {
        9
    }

    /// Uses only the current row for this isolated relation.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Reserves the quadratic degree required by each Boolean constraint.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Binds the private decomposition to one expected value.
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for ByteAir {
    /// Checks every row without relying on assignment or a private selector.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let expected = builder.public_values()[0];
        eval_byte(builder, row[0], row[1..].try_into().unwrap());
        builder.assert_eq(row[0], expected);
    }
}
