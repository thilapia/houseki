//! Linear layers of the pinned width sixteen application permutation.

use super::super::profile::WIDTH;
#[cfg(any(test, feature = "prover"))]
use crate::gadgets::Scratch;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, MATRIX_DIAG_16_GOLDILOCKS};

/// Four coordinate map used within each block of the external matrix.
const M4: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

/// Returns the public coefficient of the external block matrix.
fn coefficient(row: usize, column: usize) -> Goldilocks {
    let scale = if row / 4 == column / 4 { 2 } else { 1 };

    Goldilocks::from_u8(M4[row % 4][column % 4] * scale)
}

/// Applies external mixing to symbolic expressions without raising their degree.
pub(super) fn external<R: PrimeCharacteristicRing + From<Goldilocks>>(
    state: &[R; WIDTH],
) -> [R; WIDTH] {
    std::array::from_fn(|row| {
        state
            .iter()
            .enumerate()
            .fold(R::ZERO, |sum, (column, value)| {
                sum + value.clone() * R::from(coefficient(row, column))
            })
    })
}

/// Applies the pinned diagonal plus the sum of all coordinates.
pub(super) fn internal<R: PrimeCharacteristicRing + From<Goldilocks>>(
    state: &[R; WIDTH],
) -> [R; WIDTH] {
    let sum: R = state.iter().cloned().sum();

    std::array::from_fn(|index| {
        state[index].clone() * R::from(MATRIX_DIAG_16_GOLDILOCKS[index]) + sum.clone()
    })
}

/// Assigns external mixing using a cleared temporary owner for the next state.
#[cfg(any(test, feature = "prover"))]
pub(super) fn assign_external(state: &mut Scratch<WIDTH>) {
    let mut next = Scratch::<WIDTH>::default();
    for row in 0..WIDTH {
        for column in 0..WIDTH {
            next[row] += state[column] * coefficient(row, column);
        }
    }

    state.copy_from_slice(&*next);
}

/// Retains the shared private sum in guarded storage while updating the state in place.
#[cfg(any(test, feature = "prover"))]
pub(super) fn assign_internal(state: &mut Scratch<WIDTH>) {
    let mut sum = Scratch::<1>::default();
    for value in state.iter() {
        sum[0] += *value;
    }

    for index in 0..WIDTH {
        state[index] = state[index] * MATRIX_DIAG_16_GOLDILOCKS[index] + sum[0];
    }
}
