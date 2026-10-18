//! Test-only endpoint bindings for the complete occupied membership relation.

use super::{Endpoints, Membership};
use p3_air::{Air, AirBuilder, BaseAir, DebugConstraintBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::{dense::RowMajorMatrixView, stack::ViewPair};
use std::borrow::Cow;

/// Evaluates native-equivalent membership without admitting a payment profile.
pub(super) struct MembershipAir {
    /// Production membership constraints and assignment schedule.
    pub(super) membership: Membership,
}

impl MembershipAir {
    /// Resolves the exact fixed tree relation.
    pub(super) fn new() -> Self {
        Self {
            membership: Membership::new(),
        }
    }

    /// Evaluates one scheduled row to isolate direct trace attacks at any path level.
    pub(super) fn valid_row(
        &self,
        rows: &[Goldilocks],
        public: &[Goldilocks],
        phase: usize,
    ) -> bool {
        let width = Membership::WIDTH;
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

impl BaseAir<Goldilocks> for MembershipAir {
    /// Registers, occupancy cells and one reused hash work region.
    fn width(&self) -> usize {
        Membership::WIDTH
    }

    /// Reuses parent phase selectors across every trusted level.
    fn num_periodic_columns(&self) -> usize {
        Membership::SELECTORS
    }

    /// One complete path precedes the canonical zeroed suffix of the test trace.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        let mut columns = vec![vec![Goldilocks::ZERO; 2048]; Membership::SELECTORS];
        for row in 0..2048 {
            for (column, value) in columns.iter_mut().zip(self.periodic_values(row)) {
                column[row] = value;
            }
        }

        Cow::Owned(columns)
    }

    /// Derives public phase and level selectors directly without allocating a full table.
    fn periodic_values(&self, row_index: usize) -> Vec<Goldilocks> {
        let row = row_index % 2048;
        let mut values = vec![Goldilocks::ZERO; Membership::SELECTORS];
        if row < 21 {
            values[row] = Goldilocks::ONE;
        } else if row < 1493 {
            values[21 + (row - 21) % 23] = Goldilocks::ONE;
            values[66 + (row - 21) / 23] = Goldilocks::ONE;
        } else if row < Membership::ROWS {
            values[44 + row - 1493] = Goldilocks::ONE;
        }

        values
    }

    /// Opens live node and position registers plus internal hash bridges.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..256).chain(416..443).chain([1324]).collect()
    }

    /// Includes phase selectors and polynomial selection of the trusted level's private direction.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }

    /// Network, count, private fixture commitment and position, and expected root.
    fn num_public_values(&self) -> usize {
        216
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for MembershipAir {
    /// Applies linked membership constraints and independently zeros every inactive cell.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let phases: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|value| (*value).into())
            .collect();
        let public: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|value| (*value).into())
            .collect();
        self.membership.eval(
            builder,
            row.try_into().unwrap(),
            main.next_slice().try_into().unwrap(),
            &phases,
            Endpoints {
                network: public[..64].try_into().unwrap(),
                count: public[64..80].try_into().unwrap(),
                commitment: public[80..144].try_into().unwrap(),
                position: public[144..152].try_into().unwrap(),
                root: public[152..].try_into().unwrap(),
            },
        );
        let idle = AB::Expr::ONE - phases[..66].iter().cloned().sum::<AB::Expr>();
        for value in row {
            builder.when(idle.clone()).assert_zero(*value);
        }
    }
}
