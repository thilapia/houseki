//! Synthetic complete sponge layout reusable by framed composition tests.

use super::{assign, eval};
use crate::gadgets::poseidon2::profile::{RATE, SAMPLES, SBOXES, WIDTH};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Owns only the public block count for one isolated sponge relation.
pub(in crate::gadgets::poseidon2) struct SpongeAir {
    /// Number of already padded blocks consumed before squeezing.
    blocks: usize,
}

impl SpongeAir {
    /// Fixes a nonempty public test shape before allocating a trace.
    pub(in crate::gadgets::poseidon2) fn new(blocks: usize) -> Self {
        assert!(blocks > 0);

        Self { blocks }
    }

    /// Copies public fixture blocks and overwrites every helper and sample cell.
    pub(in crate::gadgets::poseidon2) fn assign_row(
        &self,
        blocks: &[Goldilocks],
        row: &mut [Goldilocks],
    ) {
        let (input, rest) = row.split_at_mut(self.blocks * RATE);
        input.copy_from_slice(blocks);

        self.assign_tail(input, rest);
    }

    /// Reuses already constrained block cells without introducing an unlinked input copy.
    pub(in crate::gadgets::poseidon2) fn assign_tail(
        &self,
        blocks: &[Goldilocks],
        tail: &mut [Goldilocks],
    ) {
        let count = self.blocks + 1;
        let (states, rest) = tail.split_at_mut(count * WIDTH);
        let (cubes, rest) = rest.split_at_mut(count * SBOXES);
        let (powers, samples) = rest.split_at_mut(count * SBOXES);

        assign(
            blocks.as_chunks::<RATE>().0,
            states.as_chunks_mut::<WIDTH>().0,
            cubes.as_chunks_mut::<SBOXES>().0,
            powers.as_chunks_mut::<SBOXES>().0,
            samples.try_into().unwrap(),
        )
        .unwrap();
    }

    /// Applies the internal sponge relation without exposing its blocks publicly.
    pub(in crate::gadgets::poseidon2) fn eval_row<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var],
    ) {
        let count = self.blocks + 1;
        let (blocks, rest) = row.split_at(self.blocks * RATE);
        let (states, rest) = rest.split_at(count * WIDTH);
        let (cubes, rest) = rest.split_at(count * SBOXES);
        let (powers, samples) = rest.split_at(count * SBOXES);

        eval(
            builder,
            blocks.as_chunks::<RATE>().0,
            states.as_chunks::<WIDTH>().0,
            cubes.as_chunks::<SBOXES>().0,
            powers.as_chunks::<SBOXES>().0,
            samples.try_into().unwrap(),
        );
    }
}

impl BaseAir<Goldilocks> for SpongeAir {
    /// Stores block cells, every permutation witness and eleven output samples.
    fn width(&self) -> usize {
        self.blocks * RATE + (self.blocks + 1) * (WIDTH + 2 * SBOXES) + SAMPLES
    }

    /// Keeps the synthetic relation within one row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Uses the cubic equations of the shared permutation.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }

    /// Exposes block inputs and expected samples only in the isolated test relation.
    fn num_public_values(&self) -> usize {
        self.blocks * RATE + SAMPLES
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for SpongeAir {
    /// Composes the internal relation with independently supplied public endpoints.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        self.eval_row(builder, row);

        for (index, value) in row[..self.blocks * RATE]
            .iter()
            .chain(&row[row.len() - SAMPLES..])
            .enumerate()
        {
            let expected = builder.public_values()[index];
            builder.assert_eq(*value, expected);
        }
    }
}
