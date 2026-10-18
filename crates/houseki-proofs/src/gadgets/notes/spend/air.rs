//! Test-only public endpoint bindings around complete private spend constraints.

use super::{Endpoints, Spend};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use std::borrow::Cow;

/// Isolates authority equations without native relation prechecks or profile admission.
pub(super) struct SpendAir {
    /// Complete private authority operation under test.
    pub(super) spend: Spend,
}

impl SpendAir {
    /// Selects the exact native V1 transcript schedule.
    pub(super) fn new() -> Self {
        Self {
            spend: Spend::new(),
        }
    }
}

impl BaseAir<Goldilocks> for SpendAir {
    /// Private key registers, linked digests and reused hash work cells.
    fn width(&self) -> usize {
        Spend::WIDTH
    }

    /// One trusted selector per active row of the test operation.
    fn num_periodic_columns(&self) -> usize {
        Spend::ROWS
    }

    /// Places one complete invocation before a zeroed idle suffix.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        Cow::Owned(
            (0..Spend::ROWS)
                .map(|phase| {
                    (0..128)
                        .map(|row| Goldilocks::from_bool(row == phase))
                        .collect()
                })
                .collect(),
        )
    }

    /// Opens private continuity and the hash state, sample and extraction carry bridges.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..219).chain([1100]).collect()
    }

    /// Includes trusted selector multiplication of cubic permutation equations.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }

    /// Network, ownership, commitment, position and nullifier, excluding both private keys.
    fn num_public_values(&self) -> usize {
        264
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for SpendAir {
    /// Binds every endpoint and constrains every idle cell independently of assignment.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row: &[AB::Var; 1101] = main.current_slice().try_into().unwrap();
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
        self.spend.eval(
            builder,
            row,
            main.next_slice().try_into().unwrap(),
            &phases,
            Endpoints {
                network: public[..64].try_into().unwrap(),
                ownership: public[64..128].try_into().unwrap(),
                commitment: public[128..192].try_into().unwrap(),
                position: public[192..200].try_into().unwrap(),
                nullifier: public[200..].try_into().unwrap(),
            },
        );
        let idle = AB::Expr::ONE - phases.into_iter().sum::<AB::Expr>();
        for value in row {
            builder.when(idle.clone()).assert_zero(*value);
        }
    }
}
