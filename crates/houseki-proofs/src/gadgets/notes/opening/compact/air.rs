//! Test-only complete opening relation with the frozen withdrawal semantic endpoints.

use super::CompactOpening;
use crate::statement::WithdrawalValues;
use p3_air::{Air, AirBuilder, BaseAir, DebugConstraintBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::{dense::RowMajorMatrixView, stack::ViewPair};
use std::borrow::Cow;

/// Exercises shared opening constraints without admitting a production family profile.
pub(crate) struct CompactOpeningAir {
    /// Private opening operation and its immutable source maps.
    pub(crate) opening: CompactOpening,
}

impl CompactOpeningAir {
    /// Selects the fixed shared note policy used by the test relation.
    pub(crate) fn new() -> Self {
        Self {
            opening: CompactOpening::new(),
        }
    }

    /// Evaluates one real scheduled row with its actual adjacent source cells.
    pub(crate) fn valid_row(
        &self,
        rows: &[Goldilocks],
        public: &[Goldilocks],
        phase: usize,
    ) -> bool {
        let width = CompactOpening::WIDTH;
        let next = (phase + 1) % (rows.len() / width);
        let main = ViewPair::new(
            RowMajorMatrixView::new_row(&rows[phase * width..(phase + 1) * width]),
            RowMajorMatrixView::new_row(&rows[next * width..(next + 1) * width]),
        );
        let empty = RowMajorMatrixView::new_row(&[]);
        let periodic = self.periodic_values(phase);
        let mut builder = DebugConstraintBuilder::new(
            phase,
            main,
            ViewPair::new(empty, empty),
            public,
            Goldilocks::from_bool(phase == 0),
            Goldilocks::from_bool(phase + 1 == rows.len() / width),
            Goldilocks::from_bool(phase + 1 < rows.len() / width),
            &periodic,
        );
        self.eval(&mut builder);

        builder.failures().is_empty()
    }
}

impl BaseAir<Goldilocks> for CompactOpeningAir {
    /// Stores only common private fields and bounded reusable work regions.
    fn width(&self) -> usize {
        CompactOpening::WIDTH
    }

    /// Includes the cycle-end selector which separates independent private openings.
    fn num_periodic_columns(&self) -> usize {
        CompactOpening::SELECTORS
    }

    /// Fixes all active operations and the final cycle row independently of witness values.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        Cow::Owned(
            (0..CompactOpening::SELECTORS)
                .map(|selector| {
                    let phase = if selector == 77 { 127 } else { selector };
                    (0..128)
                        .map(|row| Goldilocks::from_bool(row == phase))
                        .collect()
                })
                .collect(),
        )
    }

    /// Opens common-field continuity, internal hash bridges and crossing key coefficient bytes.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..203).chain(219..307).chain([424]).collect()
    }

    /// One immutable selector multiplies at most a cubic permutation equation.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }

    /// Network, public amount and final commitment preserve the frozen byte layout.
    fn num_public_values(&self) -> usize {
        WithdrawalValues::<Goldilocks>::LENGTH
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for CompactOpeningAir {
    /// Applies private opening constraints and exact public amount equality.
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

        for (index, byte) in CompactOpening::amount(row).iter().enumerate() {
            let expected = amount[index];
            builder
                .when(selectors[76].clone())
                .assert_eq(*byte, expected);
        }
    }
}
