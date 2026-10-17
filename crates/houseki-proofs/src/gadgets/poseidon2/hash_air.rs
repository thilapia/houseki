//! Scheduled complete application hash fixture with private intermediate field samples.

use super::{
    Frame,
    extraction::{self, ExtractionRowAir},
    permutation, sponge,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use std::borrow::Cow;

/// Composes one fixed-length part under the registered recipient key hash domain.
pub(crate) struct HashAir {
    /// Immutable public metadata shared by framing and the row schedule.
    frame: Frame,
}

impl HashAir {
    /// Selects a bounded public shape for the synthetic complete hash relation.
    pub(crate) fn new(length: &'static [usize; 1]) -> Self {
        let frame = Frame::new(b"houseki/v1/recipient/kem-key", length).unwrap();
        assert!(frame.word_len() / 7 + 17 <= 32);

        Self { frame }
    }

    /// Counts byte, bit and framed-word cells before the shared sample coordinates.
    pub(crate) fn frame_width(&self) -> usize {
        self.frame.input_len() * 9 + self.frame.word_len()
    }

    /// Counts absorption permutations and the final squeeze operation.
    fn permutations(&self) -> usize {
        self.frame.word_len() / 7 + 1
    }

    /// Assigns repeated thirty two row cycles from public byte fixtures.
    pub(crate) fn assign_trace(&self, bytes: &[Goldilocks], rows: &mut [Goldilocks]) {
        let length = self.frame.input_len();
        let frame_width = self.frame_width();
        let work = frame_width + 43;
        let mut framed = vec![Goldilocks::ZERO; frame_width];
        let (input, rest) = framed.split_at_mut(length);
        input.copy_from_slice(bytes);
        let (bits, words) = rest.split_at_mut(length * 8);
        self.frame
            .assign(&[input], &mut [bits.as_chunks_mut::<8>().0], words)
            .unwrap();

        let count = self.permutations();
        let mut states = vec![[Goldilocks::ZERO; 16]; count];
        let mut cubes = vec![[Goldilocks::ZERO; 150]; count];
        let mut powers = vec![[Goldilocks::ZERO; 150]; count];
        let mut samples = [Goldilocks::ZERO; 11];
        sponge::assign(
            words.as_chunks::<7>().0,
            &mut states,
            &mut cubes,
            &mut powers,
            &mut samples,
        )
        .unwrap();

        rows.fill(Goldilocks::ZERO);
        for (index, row) in rows.chunks_exact_mut(self.width()).enumerate() {
            row[..frame_width].copy_from_slice(&framed);
            row[frame_width..frame_width + 11].copy_from_slice(&samples);
            let phase = index % 32;
            if phase < count {
                if phase > 0 {
                    row[frame_width + 11..frame_width + 27].copy_from_slice(&states[phase - 1]);
                }

                row[frame_width + 27..work].copy_from_slice(&states[phase]);
                row[work..work + 150].copy_from_slice(&cubes[phase]);
                row[work + 150..work + 300].copy_from_slice(&powers[phase]);
            }
        }

        self.reassign_extraction(rows);
    }

    /// Recomputes downstream extraction after a test deliberately replaces the shared samples.
    pub(crate) fn reassign_extraction(&self, rows: &mut [Goldilocks]) {
        let start = self.frame_width();
        let work = start + 43;
        let mut extraction_rows = vec![Goldilocks::ZERO; 16 * 877];
        ExtractionRowAir::assign_trace(
            rows[start..start + 11].try_into().unwrap(),
            &mut extraction_rows,
        );

        for (index, row) in rows.chunks_exact_mut(self.width()).enumerate() {
            let phase = index % 32;
            if (self.permutations()..self.permutations() + 16).contains(&phase) {
                let column = phase - self.permutations();
                let source = &extraction_rows[column * 877..(column + 1) * 877];
                row[work..work + 814].copy_from_slice(&source[11..825]);
                row[work + 814..].copy_from_slice(&source[825..]);
            }
        }
    }

    /// Returns only input bytes and digest bytes for the synthetic public statement.
    pub(crate) fn public(&self, rows: &[Goldilocks]) -> Vec<Goldilocks> {
        let mut public = rows[..self.frame.input_len()].to_vec();
        let word = self.frame_width() + 857;
        for row in rows
            .chunks_exact(self.width())
            .skip(self.permutations())
            .take(16)
        {
            public.extend_from_slice(&row[word..word + 4]);
        }

        public
    }
}

impl BaseAir<Goldilocks> for HashAir {
    /// Shares one scratch region between permutation helpers and canonical sample encodings.
    fn width(&self) -> usize {
        self.frame_width() + 909
    }

    /// Supplies one fixed selector for each permutation and output word phase.
    fn num_periodic_columns(&self) -> usize {
        self.permutations() + 16
    }

    /// Repeats immutable phase selectors every thirty two rows on both proof sides.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        Cow::Owned(
            (0..self.num_periodic_columns())
                .map(|phase| {
                    (0..32)
                        .map(|row| Goldilocks::from_bool(row == phase))
                        .collect()
                })
                .collect(),
        )
    }

    /// Opens shared samples, the next permutation input and the next integer carry.
    fn main_next_row_columns(&self) -> Vec<usize> {
        let start = self.frame_width();
        (start..start + 27).chain([self.width() - 1]).collect()
    }

    /// Leaves room for a fixed phase selector multiplying a cubic substitution.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }

    /// Exposes only the input bytes and the final sixty four byte digest.
    fn num_public_values(&self) -> usize {
        self.frame.input_len() + 64
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for HashAir {
    /// Enforces complete private composition under the immutable row schedule.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let length = self.frame.input_len();
        let start = self.frame_width();
        let work = start + 43;
        let count = self.permutations();
        let values: &[AB::Var; 11] = row[start..start + 11].try_into().unwrap();

        self.frame.eval(
            builder,
            &[&row[..length]],
            &[row[length..length * 9].as_chunks::<8>().0],
            &row[length * 9..start],
        );
        for (index, value) in row[..length].iter().enumerate() {
            let expected = builder.public_values()[index];
            builder.assert_eq(*value, expected);
        }

        for index in 0..11 {
            builder
                .when_transition()
                .assert_eq(values[index], next[start + index]);
        }

        let first: AB::Expr = builder.periodic_values()[0].into();
        for value in &row[start + 11..start + 27] {
            builder.when(first.clone()).assert_zero(*value);
        }

        for phase in 0..count {
            let selector: AB::Expr = builder.periodic_values()[phase].into();
            let input = std::array::from_fn(|coordinate| {
                let mut value: AB::Expr = row[start + 11 + coordinate].into();
                if phase + 1 < count && coordinate < 7 {
                    value += row[length * 9 + phase * 7 + coordinate];
                }

                value
            });

            permutation::eval(
                &mut builder.when(selector.clone()),
                input,
                row[work..work + 150].try_into().unwrap(),
                row[work + 150..work + 300].try_into().unwrap(),
                row[start + 27..work].try_into().unwrap(),
            );

            if phase + 1 < count {
                for coordinate in 0..16 {
                    builder
                        .when_transition()
                        .when(selector.clone())
                        .assert_eq(row[start + 27 + coordinate], next[start + 11 + coordinate]);
                }
            }
        }

        let absorbed: AB::Expr = builder.periodic_values()[count - 2].into();
        for index in 0..7 {
            builder
                .when(absorbed.clone())
                .assert_eq(values[index], row[start + 27 + index]);
        }

        let squeezed: AB::Expr = builder.periodic_values()[count - 1].into();
        for index in 0..4 {
            builder
                .when(squeezed.clone())
                .assert_eq(values[index + 7], row[start + 27 + index]);
        }

        let encodings = row[work..work + 814]
            .as_chunks::<74>()
            .0
            .try_into()
            .unwrap();
        let active: AB::Expr = builder.periodic_values()[count..count + 16]
            .iter()
            .map(|value| (*value).into())
            .sum();
        extraction::eval_samples(&mut builder.when(active), values, encodings);

        for column in 0..16 {
            let selector: AB::Expr = builder.periodic_values()[count + column].into();
            extraction::eval_word(
                &mut builder.when(selector.clone()),
                encodings,
                column,
                row[work + 865].into(),
                row[work + 814..work + 818].try_into().unwrap(),
                row[work + 818..work + 850]
                    .as_chunks::<8>()
                    .0
                    .try_into()
                    .unwrap(),
                row[work + 850..work + 865].try_into().unwrap(),
            );

            for byte in 0..4 {
                let expected = builder.public_values()[length + column * 4 + byte];
                builder
                    .when(selector.clone())
                    .assert_eq(row[work + 814 + byte], expected);
            }
        }

        let first_word: AB::Expr = builder.periodic_values()[count].into();
        builder.when(first_word).assert_zero(row[work + 865]);
        let continuation: AB::Expr = builder.periodic_values()[count..count + 15]
            .iter()
            .map(|value| (*value).into())
            .sum();
        let outgoing =
            extraction::carry::<AB::Expr>(row[work + 850..work + 865].try_into().unwrap());
        builder
            .when_transition()
            .when(continuation)
            .assert_eq(next[work + 865], outgoing);
    }
}

/// Complete native vectors around both packing and sponge-padding boundaries.
#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_all_constraints;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_matrix::dense::RowMajorMatrix;

    /// Checks a supplied complete witness with public bytes following its claimed output.
    fn evaluate(air: &HashAir, rows: Vec<Goldilocks>) -> p3_air::ConstraintReport {
        let public = air.public(&rows);
        let matrix = RowMajorMatrix::new(rows, air.width());

        check_all_constraints(air, &matrix, &public, Some(32))
    }

    /// A valid extraction of replaced samples cannot bypass the private sponge links.
    #[test]
    fn every_private_sample_is_linked_to_the_sponge() {
        let air = HashAir::new(&[7]);
        let mut original = vec![Goldilocks::ZERO; air.width() * 32];
        air.assign_trace(&[Goldilocks::from_u8(0xa3); 7], &mut original);

        for sample in 0..11 {
            let mut rows = original.clone();
            for row in rows.chunks_exact_mut(air.width()) {
                row[air.frame_width() + sample] += Goldilocks::ONE;
            }

            air.reassign_extraction(&mut rows);

            assert!(!evaluate(&air, rows).is_ok(), "sample {sample}");
        }
    }

    /// Individually valid sponge and extraction phases cannot use different private samples.
    #[test]
    fn sample_continuity_binds_independent_hash_phases() {
        let air = HashAir::new(&[7]);
        let mut rows = vec![Goldilocks::ZERO; air.width() * 32];
        air.assign_trace(&[Goldilocks::from_u8(0xa3); 7], &mut rows);
        for row in rows.chunks_exact_mut(air.width()) {
            row[air.frame_width()] += Goldilocks::ONE;
        }

        air.reassign_extraction(&mut rows);
        for row in rows.chunks_exact_mut(air.width()).take(air.permutations()) {
            row[air.frame_width()] -= Goldilocks::ONE;
        }

        let report = evaluate(&air, rows);

        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].row, air.permutations() - 1);
    }

    /// Recomputing every later permutation and the digest cannot hide a broken state transition.
    #[test]
    fn state_continuity_binds_individually_valid_permutations() {
        let air = HashAir::new(&[7]);
        let width = air.width();
        let start = air.frame_width();
        let work = start + 43;
        let count = air.permutations();
        let mut rows = vec![Goldilocks::ZERO; width * 32];
        air.assign_trace(&[Goldilocks::from_u8(0xa3); 7], &mut rows);
        let mut state: [Goldilocks; 16] = rows[start + 27..work].try_into().unwrap();
        state[0] += Goldilocks::ONE;
        let mut values = [Goldilocks::ZERO; 11];
        for phase in 1..count {
            let row = &mut rows[phase * width..(phase + 1) * width];
            row[start + 11..start + 27].copy_from_slice(&state);
            if phase + 1 < count {
                for coordinate in 0..7 {
                    state[coordinate] += row[7 * 9 + phase * 7 + coordinate];
                }
            }

            let (prefix, helpers) = row.split_at_mut(work);
            let (cubes, powers) = helpers[..300].split_at_mut(150);
            let output: &mut [Goldilocks; 16] = (&mut prefix[start + 27..]).try_into().unwrap();
            permutation::assign(
                &state,
                cubes.try_into().unwrap(),
                powers.try_into().unwrap(),
                output,
            );
            state = *output;
            if phase + 2 == count {
                values[..7].copy_from_slice(&state[..7]);
            }

            if phase + 1 == count {
                values[7..].copy_from_slice(&state[..4]);
            }
        }

        for row in rows.chunks_exact_mut(width) {
            row[start..start + 11].copy_from_slice(&values);
        }

        air.reassign_extraction(&mut rows);
        let report = evaluate(&air, rows);

        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].row, 0);
    }

    /// Matches committed native vectors through every constrained hash component.
    #[test]
    fn complete_hash_matches_native_boundary_vectors() {
        for (length, expected) in [
            (
                &[0],
                "9eaca7771384bbd29d7a6ab689ebf558b05a7a0d1afbfa9dd1924798123f1c0db97518cea39f4c3b72ce77930b93db258477e3d25db9e21e46e090ae612dc301",
            ),
            (
                &[6],
                "76735931774e8ccd1202ca3b6e4ae65f31d1a740a1ab91cecc5eea82b0fd5cfb0d2782962a79ee58a6f20f96ba46c8f789ede12bbba55f5e3e326f83e5abb790",
            ),
            (
                &[7],
                "2ac400e18bd3d3ae9fae7ad903651cc85cbd5cc6d15f7ec9610e1a506279d881c48a1846763b6b3aaab643c50c620cd9cf346adc3f5fb3fde1451709a5679919",
            ),
            (
                &[41],
                "64a6b40193460ab442b2e0ac100be2faae99bde90c22a972cafd2b9d5a487c8254f297df6c2e6b99360a3cb8ccf4251b6aec816eeb20f1b5cdf46fa2982fb108",
            ),
            (
                &[42],
                "33b72595242b6afb62847735e088af243fa005dad58f9e4e905e7a629097ba0f82303bf721952d3a8b23e93a0318fd7783635217f11f11df5ce69a03a1594711",
            ),
            (
                &[48],
                "70614b29d19856c773d669fba3347e74ec8ccdbcd851e2c80bcd3a10cfc69e10a5aa7bd65ca7abf602ad9e75cc6a7e7a8058d9bb8d3f9c13e05c122ab1e3a194",
            ),
            (
                &[49],
                "200b94fdc2b1c02df7405af28a898ad0a28c34f8b10997974d9f61a4f6a4e98fb54f06d0e92714d617259b1c3e82a7872ce015aca9c8b480ee291c89d16e1fc0",
            ),
        ] {
            let air = HashAir::new(length);
            let mut rows = vec![Goldilocks::NEG_ONE; air.width() * 32];
            air.assign_trace(&vec![Goldilocks::from_u8(0xa3); length[0]], &mut rows);
            let public = air.public(&rows);
            let actual: String = public[length[0]..]
                .iter()
                .map(|value| format!("{:02x}", value.as_canonical_u64()))
                .collect();
            let matrix = RowMajorMatrix::new(rows, air.width());

            assert_eq!(actual, expected, "length {}", length[0]);
            assert!(check_all_constraints(&air, &matrix, &public, Some(8)).is_ok());
        }
    }
}
