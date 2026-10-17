//! Test-only composition of one private output opening with a frozen payment statement.

use super::OpeningAir;
use crate::statement::PaymentValues;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_goldilocks::Goldilocks;
use std::borrow::Cow;

/// Exercises output binding without claiming payment membership, nullifiers or conservation.
pub(crate) struct PaymentOpeningAir {
    /// Shared complete opening operation and fixed schedule metadata.
    inner: OpeningAir,

    /// Trusted number of input nullifiers.
    inputs: usize,

    /// Trusted number of output commitments.
    outputs: usize,

    /// Trusted output slot whose private opening is constrained.
    selected: usize,
}

impl PaymentOpeningAir {
    /// Selects a supported shape and one existing output independently of the witness.
    pub(crate) fn new(inputs: usize, outputs: usize, selected: usize) -> Self {
        assert!(PaymentValues::<Goldilocks>::length(inputs, outputs).is_some());
        assert!(selected < outputs);

        Self {
            inner: OpeningAir::new(),
            inputs,
            outputs,
            selected,
        }
    }
}

impl BaseAir<Goldilocks> for PaymentOpeningAir {
    /// Reuses exactly the complete opening trace width.
    fn width(&self) -> usize {
        self.inner.width()
    }

    /// Preserves the same number of trusted schedule selectors.
    fn num_periodic_columns(&self) -> usize {
        self.inner.num_periodic_columns()
    }

    /// Preserves all fixed operation and cycle-end selectors.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        self.inner.periodic_columns()
    }

    /// Preserves continuity and cross-row coefficient source openings.
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.inner.main_next_row_columns()
    }

    /// Output equality adds no degree beyond the shared relation.
    fn max_constraint_degree(&self) -> Option<usize> {
        self.inner.max_constraint_degree()
    }

    /// The full statement contains no recipient, private amount or private binding fields.
    fn num_public_values(&self) -> usize {
        PaymentValues::<Goldilocks>::length(self.inputs, self.outputs).unwrap()
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for PaymentOpeningAir {
    /// Links only the expected network and selected commitment while keeping note amount private.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let selectors: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|value| (*value).into())
            .collect();
        let public = PaymentValues::new(builder.public_values(), self.inputs, self.outputs)
            .expect("fixed payment shape");
        let network = public.network().map(Into::into);
        let commitment = public.commitment(self.selected).unwrap().map(Into::into);
        self.inner.opening.eval(
            builder,
            main.current_slice().try_into().unwrap(),
            main.next_slice().try_into().unwrap(),
            &selectors,
            &network,
            &commitment,
        );
    }
}
