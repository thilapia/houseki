//! Synthetic relation shared by private backend and codec tests.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

/// A private square root linked to its public square on every trace row.
pub(crate) struct SquareAir;

impl<F> BaseAir<F> for SquareAir {
    /// Stores one private root per row.
    fn width(&self) -> usize {
        1
    }

    /// Exposes exactly the expected square.
    fn num_public_values(&self) -> usize {
        1
    }

    /// Bounds the polynomial square and linear continuity constraints.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for SquareAir {
    /// Constrains the public square and continuity independently of trace preparation.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current = main.current_slice()[0];
        let next = main.next_slice()[0];
        let square = builder.public_values()[0];

        builder.assert_eq(current * current, square);
        builder.when_transition().assert_eq(current, next);
    }
}

/// Creates the synthetic witness without a public product dispatch route.
pub(crate) fn trace() -> RowMajorMatrix<Goldilocks> {
    RowMajorMatrix::new(vec![Goldilocks::from_u64(17); 512], 1)
}
