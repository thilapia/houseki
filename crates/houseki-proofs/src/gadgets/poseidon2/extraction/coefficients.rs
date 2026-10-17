//! Exact integer coefficients of the fixed Goldilocks modulus powers.

use crate::gadgets::poseidon2::profile::SAMPLES;

/// Coefficients of `(1 - B + B^2)^i`, including powers above the retained digest.
const POWERS: [[i32; 21]; SAMPLES] = powers();

/// Expands the public polynomial using exact small integer additions at compile time.
const fn powers() -> [[i32; 21]; SAMPLES] {
    let mut result = [[0; 21]; SAMPLES];
    result[0][0] = 1;
    let mut sample = 1;
    while sample < SAMPLES {
        let mut column = 0;
        while column <= 2 * (sample - 1) {
            let previous = result[sample - 1][column];
            result[sample][column] += previous;
            result[sample][column + 1] -= previous;
            result[sample][column + 2] += previous;
            column += 1;
        }

        sample += 1;
    }

    result
}

/// Returns one coefficient for a trusted sample and nonnegative polynomial column.
pub(super) fn coefficient(sample: usize, column: usize) -> i32 {
    POWERS[sample][column]
}

/// Bounds supporting integer equality instead of equality only modulo the proof field.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::poseidon2::extraction::profile::{BIAS, RADIX, WORDS};
    use p3_field::PrimeField64;
    use p3_goldilocks::Goldilocks;

    /// Pins the modulus identity and coefficient bounds used by every carry equation.
    #[test]
    fn coefficient_bounds_exclude_field_wraparound() {
        let radix = RADIX as u128;
        assert_eq!(radix * radix - radix + 1, u128::from(Goldilocks::ORDER_U64));

        for column in 0..WORDS {
            let mut positive = 0_i64;
            let mut negative = 0_i64;
            for sample in 0..SAMPLES {
                for half in 0..2 {
                    if column >= half {
                        let coefficient = i64::from(coefficient(sample, column - half));
                        positive += coefficient.max(0);
                        negative += (-coefficient).max(0);
                    }
                }
            }

            assert!(positive <= 12827 && negative <= 12826);
            let lowest = -negative * (RADIX - 1) - BIAS;
            let highest = positive * (RADIX - 1) + BIAS - 1;
            assert!(lowest.div_euclid(RADIX) >= -BIAS);
            assert!(highest.div_euclid(RADIX) < BIAS);
            assert!((highest + BIAS * RADIX) < (1_i64 << 48));
            assert!((-lowest + (BIAS - 1) * RADIX + RADIX - 1) < (1_i64 << 48));
        }
    }
}
