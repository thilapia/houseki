//! Isolated test relation for positive notes and zero-permitting bounded fee amounts.

use crate::gadgets::{AmountError, assign_amount, eval_amount};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;

/// Applies the selected amount policy and binds every amount byte to the public fixture.
pub(crate) struct AmountAir<const POSITIVE: bool>;

impl<const POSITIVE: bool> AmountAir<POSITIVE> {
    /// Cells for the amount and remainder, their bits, sixteen carries and one inverse.
    pub(crate) const WIDTH: usize = 305;

    /// Assigns public fixture values directly into an existing test row.
    pub(crate) fn assign_row(
        value: &[Goldilocks; 16],
        row: &mut [Goldilocks; 305],
    ) -> Result<(), AmountError> {
        let (amount, auxiliary) = row.split_at_mut(16);
        amount.copy_from_slice(value);
        let (remainder, auxiliary) = auxiliary.split_at_mut(16);
        let (amount_bits, auxiliary) = auxiliary.split_at_mut(128);
        let (remainder_bits, auxiliary) = auxiliary.split_at_mut(128);
        let (carries, inverse) = auxiliary.split_at_mut(16);
        assign_amount::<POSITIVE>(
            (&*amount).try_into().unwrap(),
            amount_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            remainder.try_into().unwrap(),
            remainder_bits.as_chunks_mut::<8>().0.try_into().unwrap(),
            carries.try_into().unwrap(),
            &mut inverse[0],
        )
    }
}

impl<const POSITIVE: bool> BaseAir<Goldilocks> for AmountAir<POSITIVE> {
    /// Stores the amount, remainder and all range and arithmetic auxiliaries.
    fn width(&self) -> usize {
        Self::WIDTH
    }

    /// Keeps the isolated amount relation within the current row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    /// Reserves quadratic byte, carry and positivity constraints.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Exposes every amount byte without reducing the integer modulo the field.
    fn num_public_values(&self) -> usize {
        16
    }
}

impl<const POSITIVE: bool, AB: AirBuilder<F = Goldilocks>> Air<AB> for AmountAir<POSITIVE> {
    /// Applies the shared bound and independently expected public byte values.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        eval_amount::<POSITIVE, _>(
            builder,
            row[..16].try_into().unwrap(),
            row[32..160].as_chunks::<8>().0.try_into().unwrap(),
            row[16..32].try_into().unwrap(),
            row[160..288].as_chunks::<8>().0.try_into().unwrap(),
            row[288..304].try_into().unwrap(),
            row[304],
        );

        for (index, byte) in row[..16].iter().enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*byte, expected);
        }
    }
}
