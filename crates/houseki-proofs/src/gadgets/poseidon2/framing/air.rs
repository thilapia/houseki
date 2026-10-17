//! Isolated test layout exposing the complete framed input to a future sponge.

use super::FramingError;
use crate::gadgets::HashFrame;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Applies the shared framing relation and binds only its resulting words publicly.
pub(crate) struct FramingAir {
    /// Fixed public shape for the synthetic test relation.
    pub(super) frame: HashFrame,
}

impl FramingAir {
    /// Selects trusted test metadata before computing trace dimensions.
    pub(crate) fn new(domain: &'static [u8], lengths: &'static [usize]) -> Self {
        Self {
            frame: HashFrame::new(domain, lengths).unwrap(),
        }
    }

    /// Copies public fixture bytes before assigning the decompositions and padded words.
    pub(crate) fn assign_row(
        &self,
        values: &[Goldilocks],
        row: &mut [Goldilocks],
    ) -> Result<(), FramingError> {
        let length = self.frame.input_len();
        let (input, rest) = row.split_at_mut(length);
        input.copy_from_slice(values);
        let (bits, words) = rest.split_at_mut(length * 8);
        let mut input: &[Goldilocks] = input;
        let mut bits = bits.as_chunks_mut::<8>().0;
        let mut parts = Vec::new();
        let mut decompositions = Vec::new();
        for length in self.frame.lengths {
            let (part, remaining) = input.split_at(*length);
            input = remaining;
            parts.push(part);
            let (part_bits, remaining) = bits.split_at_mut(*length);
            bits = remaining;
            decompositions.push(part_bits);
        }

        self.frame.assign(&parts, &mut decompositions, words)
    }
}

impl BaseAir<Goldilocks> for FramingAir {
    /// Stores input bytes, eight bits per byte and complete padded output blocks.
    fn width(&self) -> usize {
        self.frame.input_len() * 9 + self.frame.word_len()
    }

    /// Keeps the isolated framing test within one row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Reserves the degree required by byte Boolean constraints.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Exposes every packed and padding word independently of private input bytes.
    fn num_public_values(&self) -> usize {
        self.frame.word_len()
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for FramingAir {
    /// Composes byte ranges, complete packing and independently expected public words.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let length = self.frame.input_len();
        let (mut input, rest) = row.split_at(length);
        let (bits, words) = rest.split_at(length * 8);
        let mut bits = bits.as_chunks::<8>().0;
        let mut parts = Vec::new();
        let mut decompositions = Vec::new();
        for length in self.frame.lengths {
            let (part, remaining) = input.split_at(*length);
            input = remaining;
            parts.push(part);
            let (part_bits, remaining) = bits.split_at(*length);
            bits = remaining;
            decompositions.push(part_bits);
        }

        self.frame.eval(builder, &parts, &decompositions, words);
        for (index, word) in words.iter().enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*word, expected);
        }
    }
}
