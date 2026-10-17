//! Sixteen row extraction schedule for bounded real proof tests.

use super::{air::ExtractionAir, samples, word};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use std::borrow::Cow;

/// Repeats a complete sixteen word extraction with public samples and digest endpoints.
pub(crate) struct ExtractionRowAir;

impl ExtractionRowAir {
    /// Assigns repeated cycles from one public fixture with exact carry transitions.
    pub(crate) fn assign_trace(values: &[Goldilocks; 11], rows: &mut [Goldilocks]) {
        let mut flat = [Goldilocks::ZERO; 1641];
        ExtractionAir::assign_row(values, &mut flat);
        for (index, row) in rows.as_chunks_mut::<877>().0.iter_mut().enumerate() {
            let column = index % 16;
            row[..825].copy_from_slice(&flat[..825]);
            row[825..829].copy_from_slice(&flat[825 + 4 * column..829 + 4 * column]);
            row[829..861].copy_from_slice(&flat[889 + 32 * column..921 + 32 * column]);
            row[861..876].copy_from_slice(&flat[1401 + 15 * column..1416 + 15 * column]);
            row[876] = if column == 0 {
                Goldilocks::ZERO
            } else {
                word::carry(
                    flat[1401 + 15 * (column - 1)..1401 + 15 * column]
                        .try_into()
                        .unwrap(),
                )
            };
        }
    }
}

impl BaseAir<Goldilocks> for ExtractionRowAir {
    /// Stores shared sample encodings and one word with incoming and outgoing carries.
    fn width(&self) -> usize {
        877
    }

    /// Selects one fixed output word at each position in a sixteen row cycle.
    fn num_periodic_columns(&self) -> usize {
        16
    }

    /// Supplies public one-hot selectors computed by both prover and verifier.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        Cow::Owned(
            (0..16)
                .map(|column| {
                    (0..16)
                        .map(|row| Goldilocks::from_bool(row == column))
                        .collect()
                })
                .collect(),
        )
    }

    /// The incoming carry is the only next-row cell read by this schedule.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![876]
    }

    /// Accounts for a fixed selector multiplying quadratic bit checks.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }

    /// Binds eleven samples and all sixty four digest bytes independently of assignment.
    fn num_public_values(&self) -> usize {
        75
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for ExtractionRowAir {
    /// Enforces canonicality, each selected word and every within-cycle carry transition.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let encodings = row[11..825].as_chunks::<74>().0.try_into().unwrap();
        samples::eval(builder, row[..11].try_into().unwrap(), encodings);

        for (index, value) in row[..11].iter().enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*value, expected);
        }

        for column in 0..16 {
            let selector: AB::Expr = builder.periodic_values()[column].into();
            word::eval(
                &mut builder.when(selector.clone()),
                encodings,
                column,
                row[876].into(),
                row[825..829].try_into().unwrap(),
                row[829..861].as_chunks::<8>().0.try_into().unwrap(),
                row[861..876].try_into().unwrap(),
            );

            for byte in 0..4 {
                let expected = builder.public_values()[11 + column * 4 + byte];
                builder
                    .when(selector.clone())
                    .assert_eq(row[825 + byte], expected);
            }
        }

        let first: AB::Expr = builder.periodic_values()[0].into();
        builder.when(first).assert_zero(row[876]);
        let last: AB::Expr = builder.periodic_values()[15].into();
        let outgoing = word::carry::<AB::Expr>(row[861..876].try_into().unwrap());
        builder
            .when_transition()
            .when(AB::Expr::ONE - last)
            .assert_eq(main.next_slice()[876], outgoing);
    }
}
