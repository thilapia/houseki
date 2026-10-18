//! Complete payment relation with exact ordered links and integer conservation.

use super::{PaymentLayout, schedule::Schedule};
use crate::{
    gadgets::{
        CompactOpening, Membership, MembershipEndpoints, OpeningSelectors, Spend, SpendEndpoints,
        eval_addition,
    },
    statement::PaymentValues,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use std::borrow::Cow;

/// Composes every actual note, linked input authority, occupied path and exact public fee.
pub(crate) struct PaymentAir<'a> {
    /// Immutable geometry selected before proof decoding or private allocation.
    pub(crate) layout: &'a PaymentLayout,

    /// Shared opening constraints with the retained withdrawal algebra unchanged.
    pub(super) opening: CompactOpening,

    /// Complete authority and position-bound nullifier relation.
    pub(super) spend: Spend,

    /// Complete occupied membership under the exact expected root and count.
    pub(super) membership: Membership,
}

impl<'a> PaymentAir<'a> {
    /// Resolves shared gadgets from trusted family metadata without witness data.
    pub(crate) fn new(layout: &'a PaymentLayout) -> Self {
        Self {
            layout,
            opening: CompactOpening::new(),
            spend: Spend::new(),
            membership: Membership::new(),
        }
    }

    /// Evaluates one real scheduled row with its actual adjacent source cells.
    #[cfg(test)]
    pub(crate) fn valid_row(
        &self,
        rows: &[Goldilocks],
        public: &[Goldilocks],
        phase: usize,
    ) -> bool {
        let width = self.layout.width();
        let next = (phase + 1) % (rows.len() / width);
        let main = p3_matrix::stack::ViewPair::new(
            p3_matrix::dense::RowMajorMatrixView::new_row(
                &rows[phase * width..(phase + 1) * width],
            ),
            p3_matrix::dense::RowMajorMatrixView::new_row(&rows[next * width..(next + 1) * width]),
        );
        let empty = p3_matrix::dense::RowMajorMatrixView::new_row(&[]);
        let periodic = self.periodic_values(phase);
        let mut builder = p3_air::DebugConstraintBuilder::new(
            phase,
            main,
            p3_matrix::stack::ViewPair::new(empty, empty),
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

impl BaseAir<Goldilocks> for PaymentAir<'_> {
    /// Complete live-register and shared-work width.
    fn width(&self) -> usize {
        self.layout.width()
    }

    /// Reuses gadget phase columns across all actual note slots.
    fn num_periodic_columns(&self) -> usize {
        self.layout.schedule.selectors()
    }

    /// Constructs the complete original-domain schedule from checked public counts.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        let mut columns =
            vec![vec![Goldilocks::ZERO; self.layout.rows()]; self.num_periodic_columns()];
        for row in 0..self.layout.rows() {
            for (column, value) in columns.iter_mut().zip(self.layout.schedule.values(row)) {
                column[row] = value;
            }
        }

        Cow::Owned(columns)
    }

    /// Computes one original-domain row without materializing all periodic columns.
    fn periodic_values(&self, row_index: usize) -> Vec<Goldilocks> {
        self.layout.schedule.values(row_index % self.layout.rows())
    }

    /// Opens exactly the union of continuity and shared gadget bridges.
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.layout.next_columns()
    }

    /// Includes phase selectors without multiplying the retained opening equations by an outer gate.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }

    /// Binds every actual input nullifier and output commitment in statement order.
    fn num_public_values(&self) -> usize {
        self.layout.shape().public_values_len()
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for PaymentAir<'_> {
    /// Enforces complete operations, stable private links, once-only additions and zero padding.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let phases: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|value| (*value).into())
            .collect();
        let shape = self.layout.shape();
        let public = PaymentValues::new(builder.public_values(), shape.inputs(), shape.outputs())
            .expect("trusted payment shape");
        let network = public.network().map(Into::into);
        let count = public.count().map(Into::into);
        let root = public.root().map(Into::into);
        let fee = public.fee().map(Into::into);
        let ownership: [AB::Expr; 64] = std::array::from_fn(|index| row[48 + index].into());
        let commitment: [AB::Expr; 64] = std::array::from_fn(|index| row[112 + index].into());
        let position: [AB::Expr; 8] = std::array::from_fn(|index| row[176 + index].into());
        let nullifier: [AB::Expr; 64] = std::array::from_fn(|byte| {
            (0..shape.inputs())
                .map(|index| {
                    phases[Schedule::SLOTS + index].clone()
                        * Into::<AB::Expr>::into(public.nullifier(index).unwrap()[byte])
                })
                .sum()
        });
        let expected_output: [AB::Expr; 64] = std::array::from_fn(|byte| {
            (0..shape.outputs())
                .map(|index| {
                    phases[Schedule::SLOTS + shape.inputs() + index].clone()
                        * Into::<AB::Expr>::into(public.commitment(index).unwrap()[byte])
                })
                .sum()
        });
        let note: AB::Expr = phases[Schedule::SLOTS..].iter().cloned().sum();
        let output: AB::Expr = phases[Schedule::SLOTS + shape.inputs()..]
            .iter()
            .cloned()
            .sum();
        let addition = phases[298].clone() + phases[299].clone() + phases[300].clone();
        let work = &row[PaymentLayout::WORK..];
        let next_work = &next[PaymentLayout::WORK..];
        self.opening.eval_selected(
            builder,
            work[..CompactOpening::WIDTH].try_into().unwrap(),
            next_work[..CompactOpening::WIDTH].try_into().unwrap(),
            OpeningSelectors {
                phases: &phases[..78],
                active: phases[78].clone(),
            },
            &network,
            &commitment,
        );
        for byte in 0..64 {
            builder
                .when(phases[0].clone())
                .assert_eq(work[byte], ownership[byte].clone());
            builder
                .when(output.clone())
                .assert_eq(commitment[byte].clone(), expected_output[byte].clone());
        }

        for byte in 0..16 {
            builder
                .when(phases[0].clone())
                .assert_eq(work[64 + byte], row[32 + byte]);
        }

        for byte in &position {
            builder.when(output.clone()).assert_zero(byte.clone());
        }

        self.spend.eval(
            builder,
            work[..Spend::WIDTH].try_into().unwrap(),
            next_work[..Spend::WIDTH].try_into().unwrap(),
            &phases[79..167],
            SpendEndpoints {
                network: &network,
                ownership: &ownership,
                commitment: &commitment,
                position: &position,
                nullifier: &nullifier,
            },
        );
        self.membership.eval(
            builder,
            work[..Membership::WIDTH].try_into().unwrap(),
            next_work[..Membership::WIDTH].try_into().unwrap(),
            &phases[167..298],
            MembershipEndpoints {
                network: &network,
                count: &count,
                commitment: &commitment,
                position: &position,
                root: &root,
            },
        );
        eval_addition(
            &mut builder.when(addition.clone()),
            [
                work[..16].try_into().unwrap(),
                work[16..32].try_into().unwrap(),
            ],
            [
                work[48..176].as_chunks::<8>().0.try_into().unwrap(),
                work[176..304].as_chunks::<8>().0.try_into().unwrap(),
            ],
            work[32..48].try_into().unwrap(),
            work[304..432].as_chunks::<8>().0.try_into().unwrap(),
            work[432..448].try_into().unwrap(),
        );
        for byte in 0..16 {
            builder
                .when(phases[298].clone())
                .assert_eq(work[byte], row[byte]);
            builder
                .when(phases[299].clone() + phases[300].clone())
                .assert_eq(work[byte], row[16 + byte]);
            builder
                .when(phases[298].clone() + phases[299].clone())
                .assert_eq(work[16 + byte], row[32 + byte]);
            builder
                .when(phases[300].clone())
                .assert_eq(work[16 + byte], fee[byte].clone());
            builder
                .when(phases[300].clone())
                .assert_eq(work[32 + byte], row[byte]);
            builder.when_first_row().assert_zero(row[byte]);
            builder.when_first_row().assert_zero(row[16 + byte]);
            builder.when_transition().assert_eq(
                next[byte],
                row[byte] + phases[298].clone() * (work[32 + byte] - row[byte]),
            );
            builder.when_transition().assert_eq(
                next[16 + byte],
                row[16 + byte]
                    + (phases[299].clone() + phases[300].clone())
                        * (work[32 + byte] - row[16 + byte]),
            );
        }

        let note_continuation = note.clone() - phases[298].clone() - phases[299].clone();
        for column in 32..184 {
            builder
                .when_transition()
                .when(note_continuation.clone())
                .assert_eq(row[column], next[column]);
            builder
                .when(AB::Expr::ONE - note.clone())
                .assert_zero(row[column]);
        }

        let spend: AB::Expr = phases[79..167].iter().cloned().sum();
        let membership: AB::Expr =
            phases[167..233].iter().cloned().sum::<AB::Expr>() + phases[297].clone();
        for (column, value) in work.iter().enumerate() {
            let mut active = AB::Expr::ZERO;
            if column < 1001 {
                active += phases[78].clone();
            }

            if column < 983 {
                active += spend.clone();
            }

            if column < 991 {
                active += membership.clone();
            }

            if column < 448 {
                active += addition.clone();
            }

            builder.when(AB::Expr::ONE - active).assert_zero(*value);
        }
    }
}
