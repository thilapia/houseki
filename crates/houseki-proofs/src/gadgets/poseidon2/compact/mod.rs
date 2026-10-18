//! Payment hash work with canonical sample checks distributed across existing extraction rows.

#[cfg(test)]
mod air;
#[cfg(any(test, feature = "prover"))]
mod assignment;

use super::{
    extraction,
    framing::{Block, Frame, FramingError},
    permutation,
};
use crate::gadgets::eval_field_bytes;
use p3_air::AirBuilder;
use p3_goldilocks::Goldilocks;

/// Immutable framing and contiguous phases for one complete application hash.
///
/// The caller selects metadata from its trusted circuit and owns phase selectors, source and
/// digest links, surrounding trace storage and constraints outside this operation's phases.
pub(crate) struct CompactHash<const BLOCKS: usize> {
    /// One immutable source map per absorption operation.
    blocks: [Block; BLOCKS],

    /// Ordered source lengths checked before assignment touches any destination.
    lengths: &'static [usize],
}

impl<const BLOCKS: usize> CompactHash<BLOCKS> {
    /// Cells shared by samples, permutation states, framing and canonical digest extraction.
    pub(crate) const WIDTH: usize = 791;

    /// Absorption phases followed by one squeeze and sixteen output words.
    pub(crate) const ROWS: usize = BLOCKS + 17;

    /// Checks fixed metadata without allocating or borrowing witness material.
    ///
    /// # Errors
    ///
    /// Returns the frame's representability error or a shape mismatch if the selected block
    /// count does not exactly cover its padded transcript.
    pub(crate) fn new(
        domain: &'static [u8],
        lengths: &'static [usize],
    ) -> Result<Self, FramingError> {
        let frame = Frame::new(domain, lengths)?;
        if BLOCKS == 0 || frame.word_len() / 7 != BLOCKS {
            return Err(FramingError::ShapeMismatch);
        }

        Ok(Self {
            blocks: std::array::from_fn(|index| frame.block(index).unwrap()),
            lengths,
        })
    }

    /// Borrows trusted source coordinates for input linkage and additional input relations.
    pub(crate) fn blocks(&self) -> &[Block; BLOCKS] {
        &self.blocks
    }

    /// Constrains internal hash phases while leaving external links with the consuming circuit.
    ///
    /// Selectors must be trusted one-hot values for consecutive phases that never cross the
    /// trace's final row, with exactly one invocation per complete hash operation.
    ///
    /// The caller binds every source requiring an external relation and all digest endpoints,
    /// and constrains this work region when none of these phases is active.
    pub(crate) fn eval<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var; 791],
        next: &[AB::Var; 791],
        phases: &[AB::Expr],
    ) {
        assert_eq!(phases.len(), Self::ROWS);
        for (phase, block) in self.blocks.iter().enumerate() {
            block.eval(
                &mut builder.when(phases[phase].clone()),
                row[43..92].try_into().unwrap(),
                row[92..484].as_chunks::<8>().0.try_into().unwrap(),
                row[484..491].try_into().unwrap(),
            );
        }

        let absorbing: AB::Expr = phases[..BLOCKS].iter().cloned().sum();
        let squeeze = phases[BLOCKS].clone();
        let permuting = absorbing.clone() + squeeze.clone();
        let extracting: AB::Expr = phases[BLOCKS + 1..].iter().cloned().sum();
        for coordinate in 0..16 {
            builder
                .when(phases[0].clone())
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

        let continuing: AB::Expr = phases[..Self::ROWS - 1].iter().cloned().sum();
        for index in 0..11 {
            builder
                .when_transition()
                .when(continuing.clone())
                .assert_eq(row[index], next[index]);
            let (selector, coordinate) = if index < 7 {
                (phases[BLOCKS - 1].clone(), index)
            } else {
                (squeeze.clone(), index - 7)
            };

            builder
                .when(selector)
                .assert_eq(row[index], row[27 + coordinate]);
        }

        let encodings: [[AB::Var; 8]; 11] =
            std::array::from_fn(|sample| std::array::from_fn(|byte| row[43 + sample * 8 + byte]));
        for sample in 0..11 {
            eval_field_bytes(
                &mut builder.when(phases[BLOCKS + 1 + sample].clone()),
                row[sample],
                &encodings[sample],
                row[131..195].as_chunks::<8>().0.try_into().unwrap(),
                row[195],
                row[196],
            );
        }

        for word in 0..16 {
            extraction::eval_word_bytes(
                &mut builder.when(phases[BLOCKS + 1 + word].clone()),
                &encodings,
                word,
                row[248].into(),
                row[197..201].try_into().unwrap(),
                row[201..233].as_chunks::<8>().0.try_into().unwrap(),
                row[233..248].try_into().unwrap(),
            );
        }

        builder
            .when(phases[BLOCKS + 1].clone())
            .assert_zero(row[248]);
        let continuation: AB::Expr = phases[BLOCKS + 1..Self::ROWS - 1].iter().cloned().sum();
        builder
            .when_transition()
            .when(continuation.clone())
            .assert_eq(
                next[248],
                extraction::carry::<AB::Expr>(row[233..248].try_into().unwrap()),
            );
        for byte in 43..131 {
            builder
                .when_transition()
                .when(continuation.clone())
                .assert_eq(row[byte], next[byte]);
        }

        let unused_helpers: AB::Expr = phases[BLOCKS + 12..].iter().cloned().sum();
        for value in &row[131..197] {
            builder.when(unused_helpers.clone()).assert_zero(*value);
        }

        for value in &row[249..] {
            builder.when(extracting.clone()).assert_zero(*value);
        }

        for value in &row[11..43] {
            builder.when(extracting.clone()).assert_zero(*value);
        }

        for value in &row[43..491] {
            builder.when(squeeze.clone()).assert_zero(*value);
        }
    }

    /// Applies one complete hash with exact source maps and all sixteen digest extraction words.
    pub(crate) fn eval_linked<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        row: &[AB::Var; 791],
        next: &[AB::Var; 791],
        phases: &[AB::Expr],
        parts: &[&[AB::Expr]],
        digest: &[AB::Expr; 64],
    ) {
        self.eval(builder, row, next, phases);
        for (phase, block) in self.blocks().iter().enumerate() {
            for (local, part, offset) in block.input_positions() {
                builder
                    .when(phases[phase].clone())
                    .assert_eq(row[43 + local], parts[part][offset].clone());
            }
        }

        for word in 0..16 {
            for byte in 0..4 {
                builder
                    .when(phases[BLOCKS + 1 + word].clone())
                    .assert_eq(row[197 + byte], digest[word * 4 + byte].clone());
            }
        }
    }
}

/// Differential checks before the compact hash is used by any payment relation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::poseidon2::ScheduledHash;
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    /// Retains every native digest while reducing work width without adding rows.
    #[test]
    fn compact_hash_matches_retained_schedule_without_extra_rows() {
        let original =
            ScheduledHash::<4>::new(b"houseki/v1/ownership/spend-key", &[64, 32]).unwrap();
        let air = air::CompactHashAir::<4>::new(b"houseki/v1/ownership/spend-key", &[64, 32]);
        for byte in [0, 1, 127, 255] {
            let network = [Goldilocks::from_u8(byte); 64];
            let key = [Goldilocks::from_u8(255 - byte); 32];
            let parts: [&[Goldilocks]; 2] = [&network, &key];
            let mut retained = vec![Goldilocks::ZERO; 21 * 909];
            original.assign(&parts, &mut retained, 909).unwrap();
            let mut expected = [Goldilocks::ZERO; 64];
            original.copy_digest(&retained, 909, &mut expected);
            let mut rows = vec![Goldilocks::ZERO; 128 * 791];
            air.hash.assign(&parts, &mut rows, 791).unwrap();
            let mut actual = [Goldilocks::ZERO; 64];
            air.hash.copy_digest(&rows, 791, &mut actual);
            let mut public = network.to_vec();
            public.extend(key);
            public.extend(actual);

            assert_eq!(CompactHash::<4>::WIDTH, 791);
            assert_eq!(CompactHash::<4>::ROWS, ScheduledHash::<4>::ROWS);
            assert_eq!(actual, expected);
            assert!(
                check_all_constraints(&air, &RowMajorMatrix::new(rows, 791), &public, Some(4))
                    .is_ok()
            );
        }
    }
    /// Every application transcript size preserves the retained hash result and complete constraints.
    #[test]
    fn compact_hash_covers_all_payment_transcript_sizes() {
        differential::<5>(b"houseki/v1/note-tree/root", &[64, 4, 16, 64]);
        differential::<6>(b"houseki/v1/note-tree/node", &[64, 4, 64, 64]);
        differential::<7>(b"houseki/v1/note/commitment", &[64, 4, 64, 64, 16, 32]);
        differential::<35>(b"houseki/v1/recipient/kem-key", &[64, 4, 1568]);
    }

    /// Compares deterministic byte transcripts without relying on native key validity prechecks.
    fn differential<const BLOCKS: usize>(domain: &'static [u8], lengths: &'static [usize]) {
        let air = air::CompactHashAir::<BLOCKS>::new(domain, lengths);
        let retained = ScheduledHash::<BLOCKS>::new(domain, lengths).unwrap();
        let values: Vec<Vec<Goldilocks>> = lengths
            .iter()
            .enumerate()
            .map(|(part, length)| {
                (0..*length)
                    .map(|index| Goldilocks::from_u8((index + part * 17) as u8))
                    .collect()
            })
            .collect();
        let parts: Vec<&[Goldilocks]> = values.iter().map(Vec::as_slice).collect();
        let mut rows = vec![Goldilocks::ZERO; 128 * 791];
        let mut original = vec![Goldilocks::ZERO; 128 * 909];
        let (result, allocations, bytes) =
            crate::test_allocator::measure(|| air.hash.assign(&parts, &mut rows, 791));
        result.unwrap();
        assert_eq!((allocations, bytes), (0, 0));
        retained.assign(&parts, &mut original, 909).unwrap();
        let mut expected = [Goldilocks::ZERO; 64];
        let mut actual = [Goldilocks::ZERO; 64];
        retained.copy_digest(&original, 909, &mut expected);
        air.hash.copy_digest(&rows, 791, &mut actual);
        assert_eq!(expected, actual);
        let mut public: Vec<Goldilocks> = values.into_iter().flatten().collect();
        public.extend(actual);
        assert!(
            check_all_constraints(&air, &RowMajorMatrix::new(rows, 791), &public, Some(4)).is_ok()
        );
    }

    /// Distributed canonical bytes, selected auxiliaries and every output carry remain linked.
    #[test]
    fn compact_hash_rejects_changed_extraction_links() {
        let air = air::CompactHashAir::<4>::new(b"houseki/v1/ownership/spend-key", &[64, 32]);
        let network = [Goldilocks::ZERO; 64];
        let key = [Goldilocks::ONE; 32];
        let mut rows = vec![Goldilocks::ZERO; 128 * 791];
        air.hash.assign(&[&network, &key], &mut rows, 791).unwrap();
        let mut digest = [Goldilocks::ZERO; 64];
        air.hash.copy_digest(&rows, 791, &mut digest);
        let public: Vec<_> = network.into_iter().chain(key).chain(digest).collect();
        for word in 0..16 {
            let phase = 5 + word;
            for column in (43..131).chain([197, 200, 233, 247, 248]) {
                let index = phase * 791 + column;
                rows[index] += Goldilocks::ONE;
                assert!(
                    !air.valid_row(&rows, &public, phase)
                        || !air.valid_row(&rows, &public, phase - 1),
                    "word {word}, column {column}"
                );
                rows[index] -= Goldilocks::ONE;
            }
        }

        for sample in 0..11 {
            let phase = 5 + sample;
            for column in [131, 194, 195, 196] {
                let index = phase * 791 + column;
                rows[index] += Goldilocks::ONE;
                assert!(
                    !air.valid_row(&rows, &public, phase),
                    "sample {sample}, auxiliary {column}"
                );
                rows[index] -= Goldilocks::ONE;
            }
        }
    }
}
