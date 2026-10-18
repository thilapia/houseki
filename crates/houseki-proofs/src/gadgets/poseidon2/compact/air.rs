//! Test-only public endpoint bindings around the production scheduled hash component.

use super::CompactHash;
use p3_air::{Air, AirBuilder, BaseAir, DebugConstraintBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::{dense::RowMajorMatrixView, stack::ViewPair};
use std::borrow::Cow;

/// Exercises internal hash constraints with public synthetic inputs and final output bytes.
pub(super) struct CompactHashAir<const BLOCKS: usize> {
    /// Complete private-intermediate hash operation under test.
    pub(super) hash: CompactHash<BLOCKS>,
}

impl<const BLOCKS: usize> CompactHashAir<BLOCKS> {
    /// Selects only public fixture metadata fitting one fixed test cycle.
    pub(super) fn new(domain: &'static [u8], lengths: &'static [usize]) -> Self {
        assert!(CompactHash::<BLOCKS>::ROWS < 128);

        Self {
            hash: CompactHash::new(domain, lengths).unwrap(),
        }
    }
    /// Evaluates one real scheduled row with its actual adjacent source cells.
    pub(crate) fn valid_row(
        &self,
        rows: &[Goldilocks],
        public: &[Goldilocks],
        phase: usize,
    ) -> bool {
        let width = CompactHash::<BLOCKS>::WIDTH;
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

impl<const BLOCKS: usize> BaseAir<Goldilocks> for CompactHashAir<BLOCKS> {
    /// Reuses the production component's bounded work region.
    fn width(&self) -> usize {
        791
    }

    /// Provides one immutable selector for every active phase.
    fn num_periodic_columns(&self) -> usize {
        CompactHash::<BLOCKS>::ROWS
    }

    /// Leaves an idle suffix after each complete operation.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        Cow::Owned(
            (0..self.num_periodic_columns())
                .map(|phase| {
                    (0..128)
                        .map(|row| Goldilocks::from_bool(row == phase))
                        .collect()
                })
                .collect(),
        )
    }

    /// Opens internal state, sample and carry bridges only.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..27).chain(43..131).chain([248]).collect()
    }

    /// Includes one trusted selector multiplying cubic permutation equations.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }

    /// Exposes input and digest bytes without intermediate samples.
    fn num_public_values(&self) -> usize {
        self.hash.lengths.iter().sum::<usize>() + 64
    }
}

impl<const BLOCKS: usize, AB: AirBuilder<F = Goldilocks>> Air<AB> for CompactHashAir<BLOCKS> {
    /// Binds the production operation's endpoints and zeros its idle work cells.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let phases: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|value| (*value).into())
            .collect();
        self.hash.eval(
            builder,
            row.try_into().unwrap(),
            main.next_slice().try_into().unwrap(),
            &phases,
        );

        for (phase, block) in self.hash.blocks.iter().enumerate() {
            for (local, part, offset) in block.input_positions() {
                let expected = builder.public_values()
                    [self.hash.lengths[..part].iter().sum::<usize>() + offset];
                builder
                    .when(phases[phase].clone())
                    .assert_eq(row[43 + local], expected);
            }
        }

        let length = self.hash.lengths.iter().sum::<usize>();
        for word in 0..16 {
            for byte in 0..4 {
                let expected = builder.public_values()[length + word * 4 + byte];
                builder
                    .when(phases[BLOCKS + 1 + word].clone())
                    .assert_eq(row[197 + byte], expected);
            }
        }

        let idle = AB::Expr::ONE - phases.into_iter().sum::<AB::Expr>();
        for value in row {
            builder.when(idle.clone()).assert_zero(*value);
        }
    }
}
