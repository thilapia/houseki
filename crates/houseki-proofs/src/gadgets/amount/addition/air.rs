//! Isolated test relation linking full integer operands and their exact sum.

use crate::gadgets::{AmountError, assign_addition, eval_addition};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Applies exact addition and binds every operand and result byte to the test statement.
pub(crate) struct AdditionAir;

impl AdditionAir {
    /// Original cells for three integers, their bits and sixteen output carries.
    pub(crate) const WIDTH: usize = 448;

    /// Copies public fixture operands and assigns the rest of an existing row.
    pub(crate) fn assign_row(
        operands: [&[Goldilocks; 16]; 2],
        row: &mut [Goldilocks; Self::WIDTH],
    ) -> Result<(), AmountError> {
        let (values, auxiliary) = row.split_at_mut(48);
        values[..16].copy_from_slice(operands[0]);
        values[16..32].copy_from_slice(operands[1]);
        let (operand_cells, sum) = values.split_at_mut(32);
        let (left_bits, auxiliary) = auxiliary.split_at_mut(128);
        let (right_bits, auxiliary) = auxiliary.split_at_mut(128);
        let (sum_bits, carries) = auxiliary.split_at_mut(128);
        assign_addition(
            [
                operand_cells[..16].try_into().unwrap(),
                operand_cells[16..].try_into().unwrap(),
            ],
            [
                left_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
                right_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            ],
            sum.try_into().unwrap(),
            sum_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            carries.try_into().unwrap(),
        )
    }
}

impl BaseAir<Goldilocks> for AdditionAir {
    /// Stores both operands, the sum, every byte decomposition and each carry.
    fn width(&self) -> usize {
        Self::WIDTH
    }

    /// Keeps the isolated test relation within one row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Reserves the quadratic degree required by byte and carry Boolean constraints.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Exposes all 48 operand and result bytes without integer reduction.
    fn num_public_values(&self) -> usize {
        48
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for AdditionAir {
    /// Composes the shared relation and independently expected public byte values.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        eval_addition(
            builder,
            [
                row[..16].try_into().unwrap(),
                row[16..32].try_into().unwrap(),
            ],
            [
                row[48..176].as_chunks::<8>().0.try_into().unwrap(),
                row[176..304].as_chunks::<8>().0.try_into().unwrap(),
            ],
            row[32..48].try_into().unwrap(),
            row[304..432].as_chunks::<8>().0.try_into().unwrap(),
            row[432..].try_into().unwrap(),
        );

        for (index, value) in row[..48].iter().enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*value, expected);
        }
    }
}
