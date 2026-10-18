//! Deliberately dishonest schedule used to prove that verification reconstructs trusted selectors.

use crate::circuits::reward_withdrawal::WithdrawalAir;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use std::borrow::Cow;

/// Retains the real equations while disabling every periodic operation selector in the prover.
pub(super) struct InactiveWithdrawalAir {
    /// Complete family equations whose fixed verifier schedule must reject this substitution.
    inner: WithdrawalAir,
}

impl InactiveWithdrawalAir {
    /// Creates an adversarial configuration available only to backend tests.
    pub(super) fn new() -> Self {
        Self {
            inner: WithdrawalAir::new(),
        }
    }
}

impl BaseAir<Goldilocks> for InactiveWithdrawalAir {
    /// Preserves the honest column width to isolate schedule substitution.
    fn width(&self) -> usize {
        self.inner.width()
    }

    /// Preserves the selector count while changing their trusted evaluations.
    fn num_periodic_columns(&self) -> usize {
        self.inner.num_periodic_columns()
    }

    /// Maliciously suppresses every operation independently of the actual public amount.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        Cow::Owned(vec![
            vec![Goldilocks::ZERO; 128];
            self.num_periodic_columns()
        ])
    }

    /// Keeps the same next-row opening geometry as the real family.
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.inner.main_next_row_columns()
    }

    /// Keeps quotient dimensions equal to the honest degree bound.
    fn max_constraint_degree(&self) -> Option<usize> {
        self.inner.max_constraint_degree()
    }

    /// Uses the complete honest public vector even though the counterfeit schedule ignores it.
    fn num_public_values(&self) -> usize {
        self.inner.num_public_values()
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for InactiveWithdrawalAir {
    /// Evaluates the real relation under the deliberately incorrect periodic configuration.
    fn eval(&self, builder: &mut AB) {
        self.inner.eval(builder);
    }
}
