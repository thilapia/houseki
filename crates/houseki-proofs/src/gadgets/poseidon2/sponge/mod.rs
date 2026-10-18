//! Additive absorption of already framed blocks and the application's eleven field samples.

#[cfg(test)]
mod air;
#[cfg(any(test, feature = "prover"))]
mod error;
#[cfg(test)]
mod framed_air;

#[cfg(test)]
pub(super) use air::SpongeAir;
#[cfg(any(test, feature = "prover"))]
pub(crate) use error::SpongeError;
#[cfg(test)]
pub(crate) use framed_air::FramedSpongeAir;

use super::{
    permutation,
    profile::{RATE, SAMPLES, SBOXES, WIDTH},
};
#[cfg(any(test, feature = "prover"))]
use crate::gadgets::Scratch;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Checks trusted trace dimensions without reading any witness cells.
fn valid_shape(blocks: usize, states: usize, cubes: usize, powers: usize) -> bool {
    blocks > 0
        && blocks
            .checked_add(1)
            .is_some_and(|count| states == count && cubes == count && powers == count)
}

/// Constrains zero initialization, rate seven additive absorption and eleven ordered samples.
///
/// Each block contributes one fixed permutation and squeezing contributes one more, with
/// all sixteen coordinates preserved between operations.
///
/// The caller must constrain framing and mandatory padding on these exact input cells.
///
/// This relation produces field samples only and does not perform canonical integer extraction.
///
/// # Panics
///
/// Panics on inconsistent trusted trace dimensions before emitting constraints.
pub(super) fn eval<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    blocks: &[[AB::Var; RATE]],
    states: &[[AB::Var; WIDTH]],
    cubes: &[[AB::Var; SBOXES]],
    powers: &[[AB::Var; SBOXES]],
    samples: &[AB::Var; SAMPLES],
) {
    assert!(valid_shape(
        blocks.len(),
        states.len(),
        cubes.len(),
        powers.len()
    ));

    let mut state = std::array::from_fn(|_| AB::Expr::ZERO);
    for (index, block) in blocks.iter().enumerate() {
        for coordinate in 0..RATE {
            state[coordinate] += block[coordinate];
        }

        permutation::eval(
            builder,
            state,
            &cubes[index],
            &powers[index],
            &states[index],
        );
        state = states[index].map(Into::into);
    }

    for index in 0..RATE {
        builder.assert_eq(samples[index], state[index].clone());
    }

    let last = blocks.len();
    permutation::eval(builder, state, &cubes[last], &powers[last], &states[last]);
    for index in RATE..SAMPLES {
        builder.assert_eq(samples[index], states[last][index - RATE]);
    }
}

/// Assigns the fixed sponge schedule into borrowed buffers without allocation.
///
/// All field inputs are accepted and each destination is overwritten after shape validation.
///
/// Temporary state clears on return, while the caller retains cleanup responsibility for
/// input blocks, permutation witnesses and output samples.
///
/// Assignment does not establish constraints, so the consuming AIR must also call [`eval`].
///
/// # Errors
///
/// Returns [`SpongeError::ShapeMismatch`] before writing if there are no padded blocks or
/// any permutation buffer length differs from the block count plus one.
#[cfg(any(test, feature = "prover"))]
pub(super) fn assign(
    blocks: &[[Goldilocks; RATE]],
    states: &mut [[Goldilocks; WIDTH]],
    cubes: &mut [[Goldilocks; SBOXES]],
    powers: &mut [[Goldilocks; SBOXES]],
    samples: &mut [Goldilocks; SAMPLES],
) -> Result<(), SpongeError> {
    if !valid_shape(blocks.len(), states.len(), cubes.len(), powers.len()) {
        return Err(SpongeError::ShapeMismatch);
    }

    let mut state = Scratch::<WIDTH>::default();
    for (index, block) in blocks.iter().enumerate() {
        for coordinate in 0..RATE {
            state[coordinate] += block[coordinate];
        }

        permutation::assign(
            &state,
            &mut cubes[index],
            &mut powers[index],
            &mut states[index],
        );
        state.copy_from_slice(&states[index]);
    }

    samples[..RATE].copy_from_slice(&state[..RATE]);
    let last = blocks.len();
    permutation::assign(
        &state,
        &mut cubes[last],
        &mut powers[last],
        &mut states[last],
    );
    samples[RATE..].copy_from_slice(&states[last][..SAMPLES - RATE]);

    Ok(())
}

/// Native conformance and independently forged sponge links.
#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::{BaseAir, ConstraintReport, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::default_goldilocks_poseidon2_16;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::Permutation;

    /// Binds the public endpoints to the supplied row so a forgery cannot fail on stale public data.
    fn evaluate(air: &SpongeAir, row: &[Goldilocks], blocks: usize) -> ConstraintReport {
        let matrix = RowMajorMatrix::new(row.repeat(2), air.width());
        let public: Vec<_> = row[..blocks * RATE]
            .iter()
            .chain(&row[row.len() - SAMPLES..])
            .copied()
            .collect();

        check_all_constraints(air, &matrix, &public, Some(8))
    }

    /// Every input, intermediate output, nonlinear helper and sample participates in the relation.
    #[test]
    fn every_sponge_cell_is_constrained() {
        let air = SpongeAir::new(2);
        let blocks: Vec<_> = (1..=14).map(Goldilocks::from_usize).collect();
        let mut original = vec![Goldilocks::NEG_ONE; air.width()];
        air.assign_row(&blocks, &mut original);
        assert!(evaluate(&air, &original, 2).is_ok());

        for index in 0..original.len() {
            let mut row = original.clone();
            row[index] += Goldilocks::ONE;

            assert!(!evaluate(&air, &row, 2).is_ok(), "cell {index}");
        }
    }

    /// Honest permutation witnesses cannot hide incorrect initialization, absorption, capacity
    /// preservation or squeezing between operations.
    #[test]
    fn independently_valid_permutations_cannot_break_sponge_links() {
        let air = SpongeAir::new(2);
        for mode in 0..4 {
            let mut row = vec![Goldilocks::ZERO; air.width()];
            let (blocks, rest) = row.split_at_mut(14);
            for (index, word) in blocks.iter_mut().enumerate() {
                *word = Goldilocks::from_usize(index + 1);
            }

            let (states, rest) = rest.split_at_mut(3 * WIDTH);
            let (cubes, rest) = rest.split_at_mut(3 * SBOXES);
            let (powers, samples) = rest.split_at_mut(3 * SBOXES);
            let mut state = [Goldilocks::ZERO; WIDTH];
            if mode == 0 {
                state[RATE] = Goldilocks::ONE;
            }

            for index in 0..3 {
                if index < 2 {
                    if index == 1 && mode == 2 {
                        state[RATE..].fill(Goldilocks::ZERO);
                    }

                    for coordinate in 0..RATE {
                        if index == 1 && mode == 1 {
                            state[coordinate] = blocks[index * RATE + coordinate];
                        } else {
                            state[coordinate] += blocks[index * RATE + coordinate];
                        }
                    }
                } else {
                    samples[..RATE].copy_from_slice(&state[..RATE]);
                    if mode == 3 {
                        state[0] += Goldilocks::ONE;
                    }
                }

                let output = &mut states.as_chunks_mut::<WIDTH>().0[index];
                permutation::assign(
                    &state,
                    &mut cubes.as_chunks_mut::<SBOXES>().0[index],
                    &mut powers.as_chunks_mut::<SBOXES>().0[index],
                    output,
                );
                state = *output;
            }

            samples[RATE..].copy_from_slice(&state[..SAMPLES - RATE]);

            assert!(!evaluate(&air, &row, 2).is_ok(), "mode {mode}");
        }
    }

    /// Computes public fixture samples with the pinned native permutation directly.
    fn reference(blocks: &[[Goldilocks; RATE]]) -> [Goldilocks; SAMPLES] {
        let permutation = default_goldilocks_poseidon2_16();
        let mut state = [Goldilocks::ZERO; WIDTH];
        for block in blocks {
            for (target, value) in state[..RATE].iter_mut().zip(block) {
                *target += *value;
            }

            permutation.permute_mut(&mut state);
        }

        let mut samples = [Goldilocks::ZERO; SAMPLES];
        samples[..RATE].copy_from_slice(&state[..RATE]);
        permutation.permute_mut(&mut state);
        samples[RATE..].copy_from_slice(&state[..SAMPLES - RATE]);

        samples
    }

    /// Pins zero initialization, additive absorption, capacity and the second squeeze.
    #[test]
    fn assignment_matches_native_sponge_samples() {
        for count in 1..=4 {
            let blocks: Vec<_> = (0..count)
                .map(|block| {
                    std::array::from_fn(|index| Goldilocks::from_usize(block * RATE + index + 1))
                })
                .collect();

            let mut states = vec![[Goldilocks::NEG_ONE; WIDTH]; count + 1];
            let mut cubes = vec![[Goldilocks::NEG_ONE; SBOXES]; count + 1];
            let mut powers = cubes.clone();
            let mut samples = [Goldilocks::NEG_ONE; SAMPLES];
            assign(&blocks, &mut states, &mut cubes, &mut powers, &mut samples).unwrap();

            assert_eq!(samples, reference(&blocks));

            let air = SpongeAir::new(count);
            let mut row = vec![Goldilocks::NEG_ONE; air.width()];
            air.assign_row(blocks.as_flattened(), &mut row);

            assert!(evaluate(&air, &row, count).is_ok());
            assert_eq!(&row[row.len() - SAMPLES..], &samples);
        }
    }

    /// Every shape mismatch is rejected before any destination is modified.
    #[test]
    fn invalid_shapes_leave_all_destinations_untouched() {
        for (blocks, states, cubes, powers) in [
            (0, 1, 1, 1),
            (1, 1, 2, 2),
            (1, 2, 1, 2),
            (1, 2, 2, 1),
            (1, 3, 2, 2),
        ] {
            let blocks = vec![[Goldilocks::ONE; RATE]; blocks];
            let mut states = vec![[Goldilocks::NEG_ONE; WIDTH]; states];
            let mut cubes = vec![[Goldilocks::NEG_ONE; SBOXES]; cubes];
            let mut powers = vec![[Goldilocks::NEG_ONE; SBOXES]; powers];
            let mut samples = [Goldilocks::NEG_ONE; SAMPLES];
            let result = assign(&blocks, &mut states, &mut cubes, &mut powers, &mut samples);

            assert_eq!(result, Err(SpongeError::ShapeMismatch));
            assert!(
                states
                    .iter()
                    .flatten()
                    .chain(cubes.iter().flatten())
                    .chain(powers.iter().flatten())
                    .chain(samples.iter())
                    .all(|value| *value == Goldilocks::NEG_ONE)
            );
        }
    }
}
