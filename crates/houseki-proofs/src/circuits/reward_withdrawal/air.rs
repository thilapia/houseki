//! Withdrawal composition of the shared opening relation and public amount equality.

use crate::{gadgets::Opening, statement::WithdrawalValues};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use std::borrow::Cow;

/// Constrains one complete opening against independently reconstructed public endpoints.
pub(crate) struct WithdrawalAir {
    /// Shared constraints also used by payment output openings.
    pub(super) opening: Opening,
}

impl WithdrawalAir {
    /// Four complete cycles satisfy the backend's minimum hiding trace height.
    pub(crate) const ROWS: usize = 512;

    /// Fixes the note policy and public source maps without inspecting a witness.
    pub(crate) fn new() -> Self {
        Self {
            opening: Opening::new(),
        }
    }
}

impl BaseAir<Goldilocks> for WithdrawalAir {
    /// Retains private opening fields and reusable work cells in the shared column map.
    fn width(&self) -> usize {
        Opening::WIDTH
    }

    /// Uses trusted periodic selectors rather than witness supplied operation flags.
    fn num_periodic_columns(&self) -> usize {
        Opening::SELECTORS
    }

    /// Schedules each operation once per cycle and separates independent repeated openings.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        Cow::Owned(
            (0..Opening::SELECTORS)
                .map(|selector| {
                    let phase = if selector == 77 { 127 } else { selector };

                    (0..Opening::CYCLE)
                        .map(|row| Goldilocks::from_bool(row == phase))
                        .collect()
                })
                .collect(),
        )
    }

    /// Opens continuity, hash transitions and key coefficients crossing row boundaries.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..203)
            .chain(219..221)
            .chain(268..284)
            .chain([1084])
            .collect()
    }

    /// A trusted selector multiplies at most a cubic permutation equation.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }

    /// Binds network, positive public amount and commitment in canonical byte order.
    fn num_public_values(&self) -> usize {
        WithdrawalValues::<Goldilocks>::LENGTH
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for WithdrawalAir {
    /// Constrains the complete opening and its public amount.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice().try_into().unwrap();
        let selectors: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|value| (*value).into())
            .collect();
        let public =
            WithdrawalValues::new(builder.public_values()).expect("fixed withdrawal shape");
        let network = public.network().map(Into::into);
        let commitment = public.commitment().map(Into::into);
        let amount = *public.amount();
        self.opening.eval(
            builder,
            row,
            main.next_slice().try_into().unwrap(),
            &selectors,
            &network,
            &commitment,
        );

        for (index, byte) in Opening::amount(row).iter().enumerate() {
            builder
                .when(selectors[76].clone())
                .assert_eq(*byte, amount[index]);
        }
    }
}

/// Independent native vectors and direct malicious trace mutations at the family boundary.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::OpeningFixture;
    use p3_air::{
        DebugConstraintBuilder,
        symbolic::{AirLayout, get_max_constraint_degree},
    };
    use p3_matrix::{dense::RowMajorMatrixView, stack::ViewPair};

    /// Evaluates an actual row with its adjacent cells and the circuit's immutable selectors.
    fn valid(
        air: &WithdrawalAir,
        rows: &[Goldilocks],
        public: &[Goldilocks],
        phase: usize,
    ) -> bool {
        let width = air.width();
        let height = rows.len() / width;
        let next = (phase + 1) % height;
        let main = ViewPair::new(
            RowMajorMatrixView::new_row(&rows[phase * width..(phase + 1) * width]),
            RowMajorMatrixView::new_row(&rows[next * width..(next + 1) * width]),
        );
        let empty = RowMajorMatrixView::new_row(&[]);
        let periodic = air.periodic_values(phase);
        let mut builder = DebugConstraintBuilder::new(
            phase,
            main,
            ViewPair::new(empty, empty),
            public,
            Goldilocks::from_bool(phase == 0),
            Goldilocks::from_bool(phase + 1 == height),
            Goldilocks::from_bool(phase + 1 < height),
            &periodic,
        );
        air.eval(&mut builder);

        builder.failures().is_empty()
    }

    /// An honest commitment cannot authorize a different public amount, including high bytes.
    #[test]
    fn reward_withdrawal_air_rejects_every_public_amount_byte_change() {
        let air = WithdrawalAir::new();
        let fixture = OpeningFixture::new(1);
        let mut rows = vec![Goldilocks::ZERO; WithdrawalAir::ROWS * Opening::WIDTH];
        air.opening.assign(fixture.view(), &mut rows).unwrap();
        assert!(valid(&air, &rows, &fixture.public, 76));

        for index in 64..80 {
            let mut changed = fixture.public;
            changed[index] += Goldilocks::ONE;
            assert!(!valid(&air, &rows, &changed, 76), "amount byte {index}");
        }
    }

    /// Shared constraints reject corrupt binding, blinding, amount, key work and idle cells.
    #[test]
    fn reward_withdrawal_air_rejects_direct_trace_changes() {
        let air = WithdrawalAir::new();
        let fixture = OpeningFixture::new(0);
        let mut rows = vec![Goldilocks::ZERO; WithdrawalAir::ROWS * Opening::WIDTH];
        air.opening.assign(fixture.view(), &mut rows).unwrap();

        for (phase, column) in [
            (0, 0),
            (51, 64),
            (52, 80),
            (59, 112),
            (34, 267),
            (77, 1085),
            (127, 1492),
        ] {
            let index = phase * Opening::WIDTH + column;
            rows[index] += Goldilocks::ONE;
            assert!(
                !valid(&air, &rows, &fixture.public, phase),
                "cell {phase}:{column}"
            );
            rows[index] -= Goldilocks::ONE;
        }
    }

    /// Native commitment vectors cover minimum, high word and maximum positive amounts.
    #[test]
    fn reward_withdrawal_air_matches_native_vectors_and_degree() {
        let air = WithdrawalAir::new();
        for case in 0..3 {
            let fixture = OpeningFixture::new(case);
            let mut rows = vec![Goldilocks::ZERO; 128 * Opening::WIDTH];
            air.opening.assign(fixture.view(), &mut rows).unwrap();
            for phase in 0..128 {
                assert!(
                    valid(&air, &rows, &fixture.public, phase),
                    "case {case} phase {phase}"
                );
            }
        }

        assert_eq!(
            get_max_constraint_degree(&air, AirLayout::from_air(&air), WithdrawalAir::ROWS),
            4
        );
    }
}
