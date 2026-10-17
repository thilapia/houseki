//! Fixed width sixteen Poseidon2 permutation over guarded Goldilocks values.
//!
//! Public constants come from the pinned Plonky3 profile, while sensitive arithmetic stays
//! within the protected field implementation.

use p3_field::PrimeField64;
use p3_goldilocks::{
    GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL, GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    GOLDILOCKS_POSEIDON2_RC_16_INTERNAL, Goldilocks, MATRIX_DIAG_16_GOLDILOCKS,
};

use super::{field::FieldElement, profile::WIDTH};

/// Applies the pinned permutation in place without exposing intermediate field values.
///
/// Initial external mixing precedes four full rounds, 22 partial rounds and four final full
/// rounds, with each nonlinear step raising its input to the seventh power.
///
/// State remains owned by the caller, while replaced values and local scratch elements are
/// cleared by their field guards on return or unwinding without allocating a heap buffer.
pub(super) fn permute(state: &mut [FieldElement; WIDTH]) {
    external_linear(state);
    for constants in &GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL {
        full_round(state, constants);
    }

    for constant in GOLDILOCKS_POSEIDON2_RC_16_INTERNAL {
        partial_round(state, constant);
    }

    for constants in &GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL {
        full_round(state, constants);
    }
}

/// Mixes four element blocks and then combines their corresponding coordinates.
fn external_linear(state: &mut [FieldElement; WIDTH]) {
    for block in state.as_chunks_mut::<4>().0 {
        let first_pair = block[0].add(&block[1]);
        let second_pair = block[2].add(&block[3]);
        let sum = first_pair.add(&second_pair);
        let with_second = sum.add(&block[1]);
        let with_fourth = sum.add(&block[3]);

        // Build every coordinate before replacing the original block.
        *block = [
            with_second.add(&first_pair),
            with_second.add(&block[2].add(&block[2])),
            with_fourth.add(&second_pair),
            with_fourth.add(&block[0].add(&block[0])),
        ];
    }

    let sums: [FieldElement; 4] = std::array::from_fn(|i| {
        state[i]
            .add(&state[i + 4])
            .add(&state[i + 8])
            .add(&state[i + 12])
    });
    for (i, value) in state.iter_mut().enumerate() {
        *value = value.add(&sums[i % 4]);
    }
}

/// Applies the pinned diagonal adjustment and the sum of all coordinates.
fn internal_linear(state: &mut [FieldElement; WIDTH]) {
    let sum = state
        .iter()
        .fold(FieldElement::default(), |sum, value| sum.add(value));
    for (value, diagonal) in state.iter_mut().zip(MATRIX_DIAG_16_GOLDILOCKS) {
        *value = value.multiply(&public_constant(diagonal)).add(&sum);
    }
}

/// Adds a full round's public constants before exponentiation and external mixing.
fn full_round(state: &mut [FieldElement; WIDTH], constants: &[Goldilocks; WIDTH]) {
    for (value, constant) in state.iter_mut().zip(constants) {
        *value = seventh_power(&value.add(&public_constant(*constant)));
    }

    external_linear(state);
}

/// Updates the first coordinate with its public constant before internal mixing.
fn partial_round(state: &mut [FieldElement; WIDTH], constant: Goldilocks) {
    state[0] = seventh_power(&state[0].add(&public_constant(constant)));

    internal_linear(state);
}

/// Computes the seventh power with a fixed sequence of guarded products and squares.
fn seventh_power(value: &FieldElement) -> FieldElement {
    let square = value.square();
    let cube = square.multiply(value);
    let fourth = square.square();
    cube.multiply(&fourth)
}

/// Converts only public profile coefficients through the upstream canonical representation.
fn public_constant(value: Goldilocks) -> FieldElement {
    FieldElement::from_word(&value.as_canonical_u64())
}

/// Independent integer relations, round boundaries and pinned permutation outputs.
#[cfg(test)]
mod tests {
    use super::*;

    /// Field order expressed independently for the integer reference calculations.
    const PRIME: u128 = (1_u128 << 64) - (1_u128 << 32) + 1;

    /// Coefficients of the external four by four matrix before block combination.
    const MATRIX: [[u128; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

    /// Converts guarded values to ordinary integers only for public test fixtures.
    fn words(state: &[FieldElement; WIDTH]) -> [u128; WIDTH] {
        std::array::from_fn(|i| u128::from(*state[i].canonical_word()))
    }

    /// Evaluates the full external matrix directly rather than using the optimized additions.
    fn reference_external(state: &mut [u128; WIDTH]) {
        let input = *state;
        *state = std::array::from_fn(|row| {
            (0..WIDTH)
                .map(|column| {
                    let block_weight = if row / 4 == column / 4 { 2 } else { 1 };
                    input[column] * MATRIX[row % 4][column % 4] * block_weight
                })
                .sum::<u128>()
                % PRIME
        });
    }

    /// Evaluates the internal matrix using wide integers and canonical public coefficients.
    fn reference_internal(state: &mut [u128; WIDTH]) {
        let sum = state.iter().sum::<u128>() % PRIME;
        for (value, diagonal) in state.iter_mut().zip(MATRIX_DIAG_16_GOLDILOCKS) {
            *value = (*value * u128::from(diagonal.as_canonical_u64()) + sum) % PRIME;
        }
    }

    /// Evaluates the nonlinear relation using seven independent modular multiplications.
    fn reference_sbox(value: u128) -> u128 {
        (0..7).fold(1, |product, _| product * value % PRIME)
    }

    /// Checks every matrix column and high field values against direct matrix multiplication.
    #[test]
    fn linear_layers_match_dense_integer_matrices() {
        let cases = (0..WIDTH)
            .map(|column| std::array::from_fn(|i| u64::from(i == column)))
            .chain([
                [0; WIDTH],
                [u64::MAX; WIDTH],
                [0xffff_ffff_0000_0000; WIDTH],
            ]);

        for input in cases {
            let mut external = input.map(|word| FieldElement::from_word(&word));
            let mut internal = input.map(|word| FieldElement::from_word(&word));
            let mut expected_external = input.map(|word| u128::from(word) % PRIME);
            let mut expected_internal = expected_external;

            reference_external(&mut expected_external);
            reference_internal(&mut expected_internal);

            external_linear(&mut external);
            internal_linear(&mut internal);

            assert_eq!(words(&external), expected_external);
            assert_eq!(words(&internal), expected_internal);
        }
    }

    /// Checks the initial mixing and each full and partial round against integer arithmetic.
    #[test]
    fn every_round_matches_the_integer_reference() {
        for input in [
            [0; WIDTH],
            [u64::MAX; WIDTH],
            std::array::from_fn(|i| i as u64),
        ] {
            let mut state = input.map(|word| FieldElement::from_word(&word));
            let mut expected = input.map(|word| u128::from(word) % PRIME);

            external_linear(&mut state);
            reference_external(&mut expected);

            assert_eq!(words(&state), expected);

            for constants in GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL {
                for (value, constant) in expected.iter_mut().zip(constants) {
                    *value =
                        reference_sbox((*value + u128::from(constant.as_canonical_u64())) % PRIME);
                }
                reference_external(&mut expected);
                full_round(&mut state, &constants);

                assert_eq!(words(&state), expected);
            }

            for constant in GOLDILOCKS_POSEIDON2_RC_16_INTERNAL {
                expected[0] =
                    reference_sbox((expected[0] + u128::from(constant.as_canonical_u64())) % PRIME);
                reference_internal(&mut expected);
                partial_round(&mut state, constant);

                assert_eq!(words(&state), expected);
            }

            for constants in GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL {
                for (value, constant) in expected.iter_mut().zip(constants) {
                    *value =
                        reference_sbox((*value + u128::from(constant.as_canonical_u64())) % PRIME);
                }
                reference_external(&mut expected);
                full_round(&mut state, &constants);

                assert_eq!(words(&state), expected);
            }

            let mut complete = input.map(|word| FieldElement::from_word(&word));
            permute(&mut complete);

            assert_eq!(words(&complete), expected);
        }
    }

    /// Checks the complete schedule against the fixed upstream width sixteen vector.
    #[test]
    fn permutation_matches_the_pinned_known_answer() {
        let input = [
            0x4d3f967fab9d4979,
            0x57e1fba55677697e,
            0x57429a86e75a3774,
            0x31d379f3a592b5eb,
            0x497232e1b648e3f1,
            0x325a7db57173c39e,
            0xa802252d78bee916,
            0x8920f55e154adef8,
            0xa1225bc9c7913658,
            0xd687be5097ffd038,
            0x89f514ef0c913e48,
            0x21fd4a9cf548cd84,
            0x570a1586ada436ff,
            0x46bfbf38ccd740ae,
            0x23651b3f3ab26484,
            0xe90f3b02127fa552,
        ];
        let expected = [
            0xf0f7717837c7032a,
            0xf12fbcc838feb15b,
            0xd8661f6fa4165ad8,
            0x351cdc546760d1a9,
            0x99474334bf02445f,
            0x46fc4e9ceb376d6a,
            0x4601808321fcd920,
            0xc58bfd0342dc60df,
            0xb7f3acd43f3c029c,
            0x5c7afa6a6997dfc5,
            0xecbef8b82906c887,
            0xd490e3b4e945d87c,
            0x31866766b83ebe0b,
            0xb32d52f6e7a5bea2,
            0x9522431667b3c5f9,
            0xeaf5638a69518f65,
        ];

        let mut state = input.map(|word| FieldElement::from_word(&word));
        permute(&mut state);

        assert_eq!(words(&state), expected);
    }

    /// Checks repeated permutations against the existing provider across varied public states.
    #[test]
    fn repeated_permutations_match_the_existing_provider() {
        for seed in 0..32_u64 {
            let input = std::array::from_fn(|i| {
                seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left(i as u32 * 3)
                    ^ (i as u64).wrapping_mul(0xd1b5_4a32_d192_ed03)
            });
            let mut state = input.map(|word| FieldElement::from_word(&word));
            let mut expected = Goldilocks::new_array(input);
            for _ in 0..2 {
                permute(&mut state);
                super::super::profile::permute(&mut expected);

                assert_eq!(
                    words(&state),
                    expected.map(|value| u128::from(value.as_canonical_u64()))
                );
            }
        }
    }
}
