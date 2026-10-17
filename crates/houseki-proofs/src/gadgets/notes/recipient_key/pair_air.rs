//! Public test fixture for a packed pair of canonical recipient key coefficients.

use super::super::{RecipientKeyError, assign_recipient_pair, eval_recipient_pair};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Links three encoded bytes while keeping decomposition and bound witnesses private.
pub(crate) struct RecipientPairAir;

impl RecipientPairAir {
    /// Stores three input bytes, twenty-four byte bits and twenty-four difference bits.
    pub(crate) const WIDTH: usize = 51;

    /// Overwrites a public test row only after its complete coefficient pair is validated.
    pub(crate) fn assign_row(
        bytes: &[Goldilocks; 3],
        row: &mut [Goldilocks; 51],
    ) -> Result<(), RecipientKeyError> {
        let (values, work) = row.split_at_mut(3);
        let (bits, differences) = work.split_at_mut(24);
        assign_recipient_pair(
            bytes,
            bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            differences.as_chunks_mut::<12>().0.try_into().unwrap(),
        )?;
        values.copy_from_slice(bytes);

        Ok(())
    }
}

impl BaseAir<Goldilocks> for RecipientPairAir {
    /// Includes the complete byte and coefficient bound witnesses.
    fn width(&self) -> usize {
        Self::WIDTH
    }

    /// Keeps the test relation within the current row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Reserves the degree of Boolean range constraints.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Exposes only the three expected encoded bytes.
    fn num_public_values(&self) -> usize {
        3
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for RecipientPairAir {
    /// Applies canonical coefficient constraints and links every public byte.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let bytes = row[..3].try_into().unwrap();
        let bits = row[3..27].as_chunks::<8>().0.try_into().unwrap();
        let differences = row[27..].as_chunks::<12>().0.try_into().unwrap();
        eval_recipient_pair(builder, bytes, bits, differences);

        for (index, byte) in bytes.iter().enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*byte, expected);
        }
    }
}
