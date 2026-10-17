//! Fixed complete recipient hash schedule used only with public synthetic fixtures.

use super::{
    Frame,
    extraction::{self, ExtractionRowAir},
    framing::Block,
    permutation,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use std::borrow::Cow;

/// Composes the exact network, suite and full recipient-key hash input.
///
/// Public test inputs are linked in full, while sponge states and extraction samples remain
/// private trace cells.
///
/// This fixture establishes hashing only, without recipient-key validity or family admission.
pub(crate) struct RecipientHashAir {
    /// Immutable transcript blocks in absorption order, independent of witness data.
    blocks: [Block; 35],
}

impl RecipientHashAir {
    /// Selects the immutable recipient-binding fixture.
    pub(crate) fn new() -> Self {
        let frame = Frame::new(b"houseki/v1/recipient/kem-key", &[64, 4, 1568]).unwrap();

        Self {
            blocks: std::array::from_fn(|index| frame.block(index).unwrap()),
        }
    }

    /// Assigns public synthetic bytes into complete sixty four row cycles.
    ///
    /// Ordinary temporary arrays here hold public fixtures only and are not a production
    /// private-witness staging interface.
    pub(crate) fn assign_trace(&self, input: &[Goldilocks; 1636], rows: &mut [Goldilocks]) {
        assert!(!rows.is_empty() && rows.len().is_multiple_of(64 * self.width()));
        let parts = [&input[..64], &input[64..68], &input[68..]];
        rows.fill(Goldilocks::ZERO);
        for cycle in rows.chunks_exact_mut(64 * self.width()) {
            for (block, row) in self.blocks.iter().zip(cycle.chunks_exact_mut(self.width())) {
                let (_, scratch) = row.split_at_mut(43);
                let (values, rest) = scratch.split_at_mut(49);
                let (bits, rest) = rest.split_at_mut(392);
                block
                    .assign(
                        &parts,
                        values.try_into().unwrap(),
                        bits.as_chunks_mut::<8>().0.try_into().unwrap(),
                        (&mut rest[..7]).try_into().unwrap(),
                    )
                    .unwrap();
            }
        }

        self.reassign_sponge(rows, 0);
    }

    /// Recomputes the suffix from an existing incoming state and existing packed words.
    ///
    /// Tests can preserve a deliberately broken incoming transition while making every later
    /// permutation and extraction valid in isolation.
    pub(crate) fn reassign_sponge(&self, rows: &mut [Goldilocks], first: usize) {
        assert!(first < 36);
        let width = self.width();
        for cycle in rows.chunks_exact_mut(64 * width) {
            let mut state: [Goldilocks; 16] = cycle[first * width + 11..first * width + 27]
                .try_into()
                .unwrap();
            let mut samples: [Goldilocks; 11] = cycle[..11].try_into().unwrap();
            for (phase, row) in cycle
                .chunks_exact_mut(width)
                .enumerate()
                .take(36)
                .skip(first)
            {
                row[11..27].copy_from_slice(&state);
                for coordinate in 0..7 {
                    state[coordinate] += row[484 + coordinate];
                }

                let (prefix, helpers) = row.split_at_mut(491);
                let (cubes, powers) = helpers[..300].split_at_mut(150);
                let output: &mut [Goldilocks; 16] = (&mut prefix[27..43]).try_into().unwrap();
                permutation::assign(
                    &state,
                    cubes.try_into().unwrap(),
                    powers.try_into().unwrap(),
                    output,
                );
                state = *output;
                if phase == 34 {
                    samples[..7].copy_from_slice(&state[..7]);
                }

                if phase == 35 {
                    samples[7..].copy_from_slice(&state[..4]);
                }
            }

            for row in cycle.chunks_exact_mut(width) {
                row[..11].copy_from_slice(&samples);
            }
        }

        self.reassign_extraction(rows);
    }

    /// Recomputes extraction from each cycle's claimed samples without repairing sponge links.
    pub(crate) fn reassign_extraction(&self, rows: &mut [Goldilocks]) {
        let width = self.width();
        let mut extraction_rows = vec![Goldilocks::ZERO; 16 * 877];
        for cycle in rows.chunks_exact_mut(64 * width) {
            ExtractionRowAir::assign_trace(cycle[..11].try_into().unwrap(), &mut extraction_rows);
            for (row, source) in cycle
                .chunks_exact_mut(width)
                .skip(36)
                .take(16)
                .zip(extraction_rows.as_chunks::<877>().0)
            {
                row[43..].copy_from_slice(&source[11..]);
            }
        }
    }

    /// Returns all input and digest endpoints without exposing intermediate field samples.
    pub(crate) fn public(&self, rows: &[Goldilocks]) -> Vec<Goldilocks> {
        let mut public = vec![Goldilocks::ZERO; 1700];
        for (block, row) in self.blocks.iter().zip(rows.chunks_exact(self.width())) {
            for (local, part, offset) in block.input_positions() {
                public[[0, 64, 68][part] + offset] = row[43 + local];
            }
        }

        for (word, row) in rows
            .chunks_exact(self.width())
            .skip(36)
            .take(16)
            .enumerate()
        {
            public[1636 + word * 4..1640 + word * 4].copy_from_slice(&row[857..861]);
        }

        public
    }
}

impl BaseAir<Goldilocks> for RecipientHashAir {
    /// Reuses bounded work columns between framing, permutation and extraction.
    fn width(&self) -> usize {
        909
    }

    /// Selects thirty five blocks, one squeeze and sixteen output words.
    fn num_periodic_columns(&self) -> usize {
        52
    }

    /// Fixes the complete operation order independently on both proof sides.
    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        Cow::Owned(
            (0..52)
                .map(|phase| {
                    (0..64)
                        .map(|row| Goldilocks::from_bool(row == phase))
                        .collect()
                })
                .collect(),
        )
    }

    /// Opens sample continuity, permutation inputs and the incoming extraction carry.
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..27).chain([908]).collect()
    }

    /// Includes one fixed selector multiplying the cubic permutation constraints.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }

    /// Exposes the full ordered input and the final sixty four digest bytes only.
    fn num_public_values(&self) -> usize {
        1700
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for RecipientHashAir {
    /// Constrains every block, phase bridge, endpoint and unused scratch region.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for (phase, block) in self.blocks.iter().enumerate() {
            let selector: AB::Expr = builder.periodic_values()[phase].into();
            block.eval(
                &mut builder.when(selector.clone()),
                row[43..92].try_into().unwrap(),
                row[92..484].as_chunks::<8>().0.try_into().unwrap(),
                row[484..491].try_into().unwrap(),
            );
            for (local, part, offset) in block.input_positions() {
                let expected = builder.public_values()[[0, 64, 68][part] + offset];
                builder
                    .when(selector.clone())
                    .assert_eq(row[43 + local], expected);
            }
        }

        let absorbing: AB::Expr = builder.periodic_values()[..35]
            .iter()
            .map(|value| (*value).into())
            .sum();
        let squeeze: AB::Expr = builder.periodic_values()[35].into();
        let permuting = absorbing.clone() + squeeze.clone();
        let extracting: AB::Expr = builder.periodic_values()[36..52]
            .iter()
            .map(|value| (*value).into())
            .sum();
        let idle = AB::Expr::ONE - permuting.clone() - extracting.clone();
        let first: AB::Expr = builder.periodic_values()[0].into();
        for coordinate in 0..16 {
            builder
                .when(first.clone())
                .assert_zero(row[11 + coordinate]);
            builder
                .when_transition()
                .when(absorbing.clone())
                .assert_eq(row[27 + coordinate], next[11 + coordinate]);
        }

        permutation::eval(
            &mut builder.when(permuting.clone()),
            std::array::from_fn(|coordinate| {
                let value: AB::Expr = row[11 + coordinate].into();
                if coordinate < 7 {
                    value + row[484 + coordinate]
                } else {
                    value
                }
            }),
            row[491..641].try_into().unwrap(),
            row[641..791].try_into().unwrap(),
            row[27..43].try_into().unwrap(),
        );

        let absorbed: AB::Expr = builder.periodic_values()[34].into();
        for index in 0..11 {
            builder.when_transition().assert_eq(row[index], next[index]);
            let (selector, coordinate) = if index < 7 {
                (absorbed.clone(), index)
            } else {
                (squeeze.clone(), index - 7)
            };

            builder
                .when(selector)
                .assert_eq(row[index], row[27 + coordinate]);
        }

        let encodings = row[43..857].as_chunks::<74>().0.try_into().unwrap();
        extraction::eval_samples(
            &mut builder.when(extracting.clone()),
            row[..11].try_into().unwrap(),
            encodings,
        );
        for column in 0..16 {
            let selector: AB::Expr = builder.periodic_values()[36 + column].into();
            extraction::eval_word(
                &mut builder.when(selector.clone()),
                encodings,
                column,
                row[908].into(),
                row[857..861].try_into().unwrap(),
                row[861..893].as_chunks::<8>().0.try_into().unwrap(),
                row[893..908].try_into().unwrap(),
            );
            for byte in 0..4 {
                let expected = builder.public_values()[1636 + column * 4 + byte];
                builder
                    .when(selector.clone())
                    .assert_eq(row[857 + byte], expected);
            }
        }

        let first_word: AB::Expr = builder.periodic_values()[36].into();
        builder.when(first_word).assert_zero(row[908]);
        let continuation: AB::Expr = builder.periodic_values()[36..51]
            .iter()
            .map(|value| (*value).into())
            .sum();
        builder.when_transition().when(continuation).assert_eq(
            next[908],
            extraction::carry::<AB::Expr>(row[893..908].try_into().unwrap()),
        );

        for value in &row[11..43] {
            builder
                .when(AB::Expr::ONE - permuting.clone())
                .assert_zero(*value);
        }

        for value in &row[43..491] {
            builder.when(squeeze.clone()).assert_zero(*value);
        }

        for value in &row[791..] {
            builder.when(permuting.clone()).assert_zero(*value);
        }

        for value in &row[43..] {
            builder.when(idle.clone()).assert_zero(*value);
        }
    }
}

/// Complete vectors and attacks against the links between individually valid components.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::{RecipientHashAir, assign_byte};
    use p3_air::{ConstraintReport, DebugConstraintBuilder, check_all_constraints};
    use p3_field::PrimeField64;
    use p3_matrix::{
        dense::{RowMajorMatrix, RowMajorMatrixView},
        stack::ViewPair,
    };

    /// Assigns the independently specified recipient vector with selectable seed bytes.
    fn fixture(seed: u8, cycles: usize) -> Vec<Goldilocks> {
        let air = RecipientHashAir::new();
        let mut input = [Goldilocks::ZERO; 1636];
        for (index, value) in input[..64].iter_mut().enumerate() {
            *value = Goldilocks::from_usize(index);
        }

        input[64] = Goldilocks::ONE;
        input[1604..].fill(Goldilocks::from_u8(seed));
        let mut rows = vec![Goldilocks::NEG_ONE; air.width() * 64 * cycles];
        air.assign_trace(&input, &mut rows);

        rows
    }

    /// Checks all schedule rows while following the claimed input and digest endpoints.
    fn evaluate(air: &RecipientHashAir, rows: Vec<Goldilocks>) -> ConstraintReport {
        let public = air.public(&rows);
        let matrix = RowMajorMatrix::new(rows, air.width());

        check_all_constraints(air, &matrix, &public, Some(32))
    }

    /// Evaluates one actual row with trusted selectors to isolate public input binding attacks.
    fn failures_at(
        air: &RecipientHashAir,
        rows: &[Goldilocks],
        public: &[Goldilocks],
        phase: usize,
    ) -> usize {
        let width = air.width();
        let row = &rows[phase * width..(phase + 1) * width];
        let next = &rows[(phase + 1) * width..(phase + 2) * width];
        let periodic = air.periodic_values(phase);
        let mut builder = DebugConstraintBuilder::<Goldilocks>::new(
            phase,
            ViewPair::new(
                RowMajorMatrixView::new_row(row),
                RowMajorMatrixView::new_row(next),
            ),
            ViewPair::new(
                RowMajorMatrixView::new(&[], 0),
                RowMajorMatrixView::new(&[], 0),
            ),
            public,
            Goldilocks::from_bool(phase == 0),
            Goldilocks::ZERO,
            Goldilocks::ONE,
            &periodic,
        );
        air.eval(&mut builder);

        builder.failures().len()
    }

    /// Missing blocks, wrong part order or missing extraction change the native digest.
    #[test]
    fn complete_recipient_hash_matches_native_vector() {
        let air = RecipientHashAir::new();
        for (seed, expected) in [
            (
                0,
                "f001ec9a7577a1366a3f0742913a65fa1530446a8df7c9db52896d0459b514acfdbe01363ce585fb1473cf32a9ba8602a235e57a0f5f016f95d7c157590a7b7c",
            ),
            (
                255,
                "9e299d404d652227b2da6416279f8dfcfc40082de26259aaf6ad8e97803e4301db18de1923f8cce234521ff67c7dd3a70bf333aba8dd2a8430520557c9a6c8ef",
            ),
        ] {
            let rows = fixture(seed, 2);
            let public = air.public(&rows);
            let digest: String = public[1636..]
                .iter()
                .map(|value| format!("{:02x}", value.as_canonical_u64()))
                .collect();

            assert_eq!(digest, expected);
            assert_eq!(public.len(), 1700);
            assert!(evaluate(&air, rows).is_ok());
        }
    }

    /// Varied canonical polynomial bytes detect reordered blocks even when zero-key vectors agree.
    #[cfg(feature = "prover")]
    #[test]
    fn varied_recipient_matches_the_native_operation() {
        use houseki_crypto::{CryptoSuite, MlKem1024EncapsulationKey};
        use houseki_types::{EncodedMlKem1024PublicKey, NetworkId};

        let network = std::array::from_fn::<_, 64, _>(|index| u8::try_from(index * 3).unwrap());
        let mut key = [0_u8; 1568];
        for (index, pair) in key[..1536].as_chunks_mut::<3>().0.iter_mut().enumerate() {
            let first = (index * 19 % 3329) as u16;
            let second = ((index * 31 + 1) % 3329) as u16;
            pair[0] = first as u8;
            pair[1] = ((first >> 8) | (second << 4)) as u8;
            pair[2] = (second >> 4) as u8;
        }

        for (index, byte) in key[1536..].iter_mut().enumerate() {
            *byte = u8::try_from(index * 7).unwrap();
        }

        let validated =
            MlKem1024EncapsulationKey::try_from(&EncodedMlKem1024PublicKey::from_bytes(key))
                .unwrap();
        let expected = CryptoSuite::V1
            .recipient_key_binding(NetworkId::from_bytes(network), &validated)
            .unwrap();
        let mut input = [Goldilocks::ZERO; 1636];
        input[..64].copy_from_slice(&network.map(Goldilocks::from_u8));
        input[64] = Goldilocks::ONE;
        input[68..].copy_from_slice(&key.map(Goldilocks::from_u8));
        let air = RecipientHashAir::new();
        let mut rows = vec![Goldilocks::ZERO; air.width() * 64];
        air.assign_trace(&input, &mut rows);
        let public = air.public(&rows);

        assert_eq!(&public[..1636], &input);
        assert_eq!(&public[1636..], &expected.map(Goldilocks::from_u8));
        assert!(evaluate(&air, rows).is_ok());
    }

    /// Every source byte and digest byte has its own exact public-coordinate equality.
    #[test]
    fn every_public_endpoint_is_bound_at_its_expected_row() {
        let air = RecipientHashAir::new();
        let rows = fixture(255, 1);
        let mut public = air.public(&rows);
        for index in 0..1700 {
            let phase = match index {
                0..64 => (50 + index) / 49,
                64..68 => (122 + index - 64) / 49,
                68..1636 => (134 + index - 68) / 49,
                _ => 36 + (index - 1636) / 4,
            };
            public[index] += Goldilocks::ONE;

            assert_eq!(
                failures_at(&air, &rows, &public, phase),
                1,
                "endpoint {index}"
            );

            public[index] -= Goldilocks::ONE;
        }
    }

    /// Correct downstream permutations and extraction cannot hide a broken incoming state.
    #[test]
    fn recomputed_suffix_preserves_state_transition_rejection() {
        let air = RecipientHashAir::new();
        for phase in [0, 1, 2, 34, 35] {
            let mut rows = fixture(255, 1);
            rows[phase * air.width() + 11] += Goldilocks::ONE;
            air.reassign_sponge(&mut rows, phase);
            let report = evaluate(&air, rows);

            assert_eq!(report.failures.len(), 1, "phase {phase}");
            assert_eq!(report.failures[0].row, phase.saturating_sub(1));
        }
    }

    /// Individually valid extraction cannot choose any of its eleven input samples freely.
    #[test]
    fn all_private_samples_are_bound_to_their_sponge_outputs() {
        let air = RecipientHashAir::new();
        for sample in 0..11 {
            let mut rows = fixture(255, 1);
            for row in rows.chunks_exact_mut(air.width()) {
                row[sample] += Goldilocks::ONE;
            }

            air.reassign_extraction(&mut rows);
            let report = evaluate(&air, rows);

            assert_eq!(report.failures.len(), 1, "sample {sample}");
            assert_eq!(report.failures[0].row, if sample < 7 { 34 } else { 35 });
        }
    }

    /// Separately valid sponge and extraction phases cannot disagree at their shared boundary.
    #[test]
    fn sample_transition_joins_valid_hash_phases() {
        let air = RecipientHashAir::new();
        let mut rows = fixture(255, 1);
        for row in rows.chunks_exact_mut(air.width()) {
            row[0] += Goldilocks::ONE;
        }

        air.reassign_extraction(&mut rows);
        for row in rows.chunks_exact_mut(air.width()).take(36) {
            row[0] -= Goldilocks::ONE;
        }

        let report = evaluate(&air, rows);

        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].row, 35);
    }

    /// Repacked framing attacks remain invalid after recomputing the entire hash suffix.
    #[test]
    fn fixed_metadata_and_padding_cannot_follow_a_forged_hash() {
        let air = RecipientHashAir::new();
        for (phase, local) in [(0, 0), (0, 10), (2, 16), (34, 36), (34, 42)] {
            let mut rows = fixture(255, 1);
            let row = &mut rows[phase * air.width()..(phase + 1) * air.width()];
            row[43 + local] += Goldilocks::ONE;
            let byte = row[43 + local];
            assign_byte(
                &byte,
                (&mut row[92 + local * 8..100 + local * 8])
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
            row[484 + local / 7] += Goldilocks::from_u64(1 << (8 * (local % 7)));
            air.reassign_sponge(&mut rows, phase);
            let report = evaluate(&air, rows);

            assert_eq!(report.failures.len(), 1, "phase {phase}, local {local}");
            assert_eq!(report.failures[0].row, phase);
        }
    }

    /// The word carry and zero-work phases remain constrained at the first and last trace cycle.
    #[test]
    fn carry_boundaries_and_unused_cells_reject_changes() {
        let air = RecipientHashAir::new();
        let original = fixture(255, 2);
        for (phase, column) in [
            (0, 791),
            (35, 43),
            (36, 11),
            (36, 908),
            (37, 908),
            (51, 893),
            (52, 43),
            (63, 908),
            (64, 11),
            (115, 893),
            (127, 43),
        ] {
            let mut rows = original.clone();
            rows[phase * air.width() + column] += Goldilocks::ONE;

            assert!(
                !evaluate(&air, rows).is_ok(),
                "phase {phase}, column {column}"
            );
        }
    }
}
