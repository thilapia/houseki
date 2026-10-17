//! Isolated fixed-width fixture for a trusted absorption block.

use super::{Block, Frame, FramingError};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Binds all seven packed words while keeping variable byte cells private.
pub(crate) struct BlockAir {
    /// Public block metadata selected before witness assignment or evaluation.
    pub(super) block: Block,
}

impl BlockAir {
    /// Selects one public frame and block without retaining any witness values.
    pub(crate) fn new(domain: &'static [u8], lengths: &'static [usize], index: usize) -> Self {
        Self {
            block: Frame::new(domain, lengths).unwrap().block(index).unwrap(),
        }
    }

    /// Assigns public test fixtures into one fixed-width row.
    pub(crate) fn assign_row(
        &self,
        parts: &[&[Goldilocks]],
        row: &mut [Goldilocks],
    ) -> Result<(), FramingError> {
        let (values, rest) = row.split_at_mut(49);
        let (bits, words) = rest.split_at_mut(392);

        self.block.assign(
            parts,
            values.try_into().unwrap(),
            bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            words.try_into().unwrap(),
        )
    }
}

impl BaseAir<Goldilocks> for BlockAir {
    /// Uses 49 byte cells, 392 bit cells and seven packed words for every input length.
    fn width(&self) -> usize {
        448
    }

    /// Keeps the isolated component within a single row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Accounts for the Boolean range checks.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Exposes exactly one complete absorption block.
    fn num_public_values(&self) -> usize {
        7
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for BlockAir {
    /// Applies the owned block constraints and binds every resulting word publicly.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        self.block.eval(
            builder,
            row[..49].try_into().unwrap(),
            row[49..441].as_chunks::<8>().0.try_into().unwrap(),
            row[441..].try_into().unwrap(),
        );
        for (index, word) in row[441..].iter().enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*word, expected);
        }
    }
}
