//! Synthetic permutation layout shared by constraint and real proof tests.

use super as permutation;
use crate::gadgets::poseidon2::profile::{SBOXES, WIDTH};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Binds both ends of one fixed permutation independently of its helper cells.
pub(crate) struct PermutationAir;

impl PermutationAir {
    /// Copies a public fixture before filling every nonlinear helper and output cell.
    pub(crate) fn assign_row(input: &[Goldilocks; WIDTH], row: &mut [Goldilocks]) {
        let (endpoints, helpers) = row.split_at_mut(2 * WIDTH);
        endpoints[..WIDTH].copy_from_slice(input);
        let (cubes, powers) = helpers.split_at_mut(SBOXES);
        permutation::assign(
            input,
            cubes.try_into().unwrap(),
            powers.try_into().unwrap(),
            (&mut endpoints[WIDTH..]).try_into().unwrap(),
        );
    }
}

impl BaseAir<Goldilocks> for PermutationAir {
    /// Stores sixteen input and output cells plus two helpers per seventh power.
    fn width(&self) -> usize {
        2 * WIDTH + 2 * SBOXES
    }

    /// Keeps the synthetic relation entirely within one row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Reserves cubic equations for each nonlinear operation.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }

    /// Exposes only the independently expected input and output coordinates.
    fn num_public_values(&self) -> usize {
        2 * WIDTH
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for PermutationAir {
    /// Applies the complete schedule and binds its endpoints publicly.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        permutation::eval(
            builder,
            std::array::from_fn(|index| row[index].into()),
            row[32..182].try_into().unwrap(),
            row[182..332].try_into().unwrap(),
            row[16..32].try_into().unwrap(),
        );

        for (index, value) in row[..32].iter().enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*value, expected);
        }
    }
}
