//! Fixed width sixteen Poseidon2 relation with degree three helper constraints.

use super::linear;
use super::profile::{SBOXES, WIDTH};
#[cfg(any(test, feature = "prover"))]
use crate::gadgets::Scratch;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{
    GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL as FINAL,
    GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL as INITIAL,
    GOLDILOCKS_POSEIDON2_RC_16_INTERNAL as INTERNAL, Goldilocks,
};

/// Constrains the pinned initial mixing, four full rounds, twenty two partial rounds and
/// four final full rounds using 316 equations of degree at most three.
///
/// The caller supplies linear input expressions and owns all trace cells and scheduling.
///
/// Each substitution records its cube and seventh power, so subsequent linear layers remain
/// linear expressions in helper cells instead of increasing the constraint degree.
pub(super) fn eval<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    input: [AB::Expr; WIDTH],
    cubes: &[AB::Var; SBOXES],
    powers: &[AB::Var; SBOXES],
    output: &[AB::Var; WIDTH],
) {
    let mut state = linear::external(&input);
    let mut next = 0;
    for constants in INITIAL {
        for index in 0..WIDTH {
            state[index] = substitute(
                builder,
                state[index].clone() + constants[index],
                cubes[next],
                powers[next],
            );
            next += 1;
        }

        state = linear::external(&state);
    }

    for constant in INTERNAL {
        state[0] = substitute(
            builder,
            state[0].clone() + constant,
            cubes[next],
            powers[next],
        );
        next += 1;
        state = linear::internal(&state);
    }

    for constants in FINAL {
        for index in 0..WIDTH {
            state[index] = substitute(
                builder,
                state[index].clone() + constants[index],
                cubes[next],
                powers[next],
            );
            next += 1;
        }

        state = linear::external(&state);
    }

    for (expected, actual) in state.into_iter().zip(output) {
        builder.assert_eq(*actual, expected);
    }
}

/// Binds both nonlinear helpers before returning the stored seventh power as a linear term.
fn substitute<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    value: AB::Expr,
    cube: AB::Var,
    power: AB::Var,
) -> AB::Expr {
    builder.assert_eq(cube, value.cube());
    builder.assert_eq(power, AB::Expr::from(cube).square() * value);

    power.into()
}

/// Assigns every nonlinear helper and final coordinate in caller owned storage.
///
/// All field inputs are accepted and every destination is overwritten without allocation.
///
/// Temporary states and shifted coordinates clear on return, while the caller retains cleanup
/// responsibility for the borrowed input and destination cells.
///
/// Assignment does not establish constraints, so the consuming AIR must also call [`eval`].
#[cfg(any(test, feature = "prover"))]
pub(super) fn assign(
    input: &[Goldilocks; WIDTH],
    cubes: &mut [Goldilocks; SBOXES],
    powers: &mut [Goldilocks; SBOXES],
    output: &mut [Goldilocks; WIDTH],
) {
    let mut state = Scratch::<WIDTH>::default();
    state.copy_from_slice(input);
    linear::assign_external(&mut state);

    let mut next = 0;
    let mut shifted = Scratch::<1>::default();
    for constants in INITIAL {
        for index in 0..WIDTH {
            shifted[0] = state[index] + constants[index];
            cubes[next] = shifted[0].cube();
            powers[next] = cubes[next].square() * shifted[0];
            state[index] = powers[next];
            next += 1;
        }

        linear::assign_external(&mut state);
    }

    for constant in INTERNAL {
        shifted[0] = state[0] + constant;
        cubes[next] = shifted[0].cube();
        powers[next] = cubes[next].square() * shifted[0];
        state[0] = powers[next];
        next += 1;
        linear::assign_internal(&mut state);
    }

    for constants in FINAL {
        for index in 0..WIDTH {
            shifted[0] = state[index] + constants[index];
            cubes[next] = shifted[0].cube();
            powers[next] = cubes[next].square() * shifted[0];
            state[index] = powers[next];
            next += 1;
        }

        linear::assign_external(&mut state);
    }

    output.copy_from_slice(&*state);
}

/// Independent permutation vectors and malicious nonlinear witnesses.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::PermutationAir;
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_goldilocks::default_goldilocks_poseidon2_16;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::Permutation;

    /// Checks supplied cells with public endpoints following any attempted forgery.
    fn evaluate(row: &[Goldilocks; 332]) -> ConstraintReport {
        let matrix = RowMajorMatrix::new(row.repeat(2), 332);
        check_all_constraints(&PermutationAir, &matrix, &row[..32], Some(8))
    }

    /// Starts with occupied storage so assignment must overwrite every helper.
    fn assigned(input: &[Goldilocks; WIDTH]) -> [Goldilocks; 332] {
        let mut row = [Goldilocks::NEG_ONE; 332];
        PermutationAir::assign_row(input, &mut row);

        row
    }

    /// Replays public fixture arithmetic after changing one cube or seventh power.
    ///
    /// All later cells remain internally consistent, isolating the missing equation that
    /// would otherwise permit the forged output.
    fn forged(index: usize, cube: bool) -> [Goldilocks; 332] {
        let input = std::array::from_fn(|index| Goldilocks::from_usize(index + 1));
        let mut row = [Goldilocks::ZERO; 332];
        row[..16].copy_from_slice(&input);
        let mut state = linear::external(&input);
        let mut next = 0;
        for round in 0..30 {
            let partial = (4..26).contains(&round);
            for coordinate in 0..if partial { 1 } else { WIDTH } {
                let constant = match round {
                    0..4 => INITIAL[round][coordinate],
                    4..26 => INTERNAL[round - 4],
                    _ => FINAL[round - 26][coordinate],
                };

                let shifted = state[coordinate] + constant;
                row[32 + next] = shifted.cube();
                if next == index && cube {
                    row[32 + next] += Goldilocks::ONE;
                }

                row[182 + next] = row[32 + next].square() * shifted;
                if next == index && !cube {
                    row[182 + next] += Goldilocks::ONE;
                }

                state[coordinate] = row[182 + next];
                next += 1;
            }

            state = if partial {
                linear::internal(&state)
            } else {
                linear::external(&state)
            };
        }

        row[16..32].copy_from_slice(&state);

        row
    }

    /// Covers zero, maximal coordinates, basis vectors and varied public states against
    /// the pinned native implementation over two consecutive permutations.
    #[test]
    fn assignment_and_constraints_match_native_permutation() {
        let mut inputs = vec![
            [Goldilocks::ZERO; WIDTH],
            [Goldilocks::ONE; WIDTH],
            [Goldilocks::NEG_ONE; WIDTH],
        ];
        for coordinate in 0..WIDTH {
            let mut input = [Goldilocks::ZERO; WIDTH];
            input[coordinate] = Goldilocks::ONE;
            inputs.push(input);
        }

        for seed in 0..16 {
            inputs.push(std::array::from_fn(|index| {
                Goldilocks::from_u64(
                    (Goldilocks::ORDER_U64 - 1).wrapping_mul(31 * seed + index as u64),
                )
            }));
        }

        let permutation = default_goldilocks_poseidon2_16();
        for mut input in inputs {
            for _ in 0..2 {
                let row = assigned(&input);
                permutation.permute_mut(&mut input);

                assert_eq!(&row[16..32], &input);
                assert!(evaluate(&row).is_ok());
            }
        }
    }

    /// Every coordinate and helper is constrained even when public endpoints follow it.
    #[test]
    fn every_permutation_cell_is_constrained() {
        let original = assigned(&std::array::from_fn(Goldilocks::from_usize));
        for index in 0..332 {
            let mut row = original;
            row[index] += Goldilocks::ONE;

            assert!(!evaluate(&row).is_ok(), "cell {index}");
        }
    }

    /// Reassigning every later operation cannot hide either nonlinear equation's violation.
    #[test]
    fn coordinated_helper_forgery_is_rejected_at_every_substitution() {
        for index in 0..SBOXES {
            for cube in [false, true] {
                assert!(
                    !evaluate(&forged(index, cube)).is_ok(),
                    "substitution {index}, cube {cube}"
                );
            }
        }
    }

    /// Pins the entire round schedule to the native width sixteen known answer.
    #[test]
    fn assignment_matches_fixed_known_answer() {
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
        ]
        .map(Goldilocks::from_u64);
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
        ]
        .map(Goldilocks::from_u64);
        let mut cubes = [Goldilocks::NEG_ONE; SBOXES];
        let mut powers = [Goldilocks::NEG_ONE; SBOXES];
        let mut output = [Goldilocks::NEG_ONE; WIDTH];
        assign(&input, &mut cubes, &mut powers, &mut output);

        assert_eq!(output, expected);
    }
}
