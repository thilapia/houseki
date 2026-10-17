//! Bounded complete hash operations embedded in a caller's fixed trace schedule.

#[cfg(test)]
mod air;
#[cfg(any(test, feature = "prover"))]
mod assignment;

use super::{
    extraction,
    framing::{Block, Frame, FramingError},
    permutation,
};
use p3_air::AirBuilder;
use p3_goldilocks::Goldilocks;

/// Immutable framing and contiguous phases for one complete application hash.
///
/// The caller selects metadata from its trusted circuit and owns phase selectors, source and
/// digest links, surrounding trace storage and constraints outside this operation's phases.
pub(crate) struct ScheduledHash<const BLOCKS: usize> {
    /// One immutable source map per absorption operation.
    blocks: [Block; BLOCKS],

    /// Ordered source lengths checked before assignment touches any destination.
    lengths: &'static [usize],
}

impl<const BLOCKS: usize> ScheduledHash<BLOCKS> {
    /// Cells shared by samples, permutation states, framing and canonical digest extraction.
    pub(crate) const WIDTH: usize = 909;

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
        row: &[AB::Var; 909],
        next: &[AB::Var; 909],
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

        let encodings = row[43..857].as_chunks::<74>().0.try_into().unwrap();
        extraction::eval_samples(
            &mut builder.when(extracting.clone()),
            row[..11].try_into().unwrap(),
            encodings,
        );
        for column in 0..16 {
            extraction::eval_word(
                &mut builder.when(phases[BLOCKS + 1 + column].clone()),
                encodings,
                column,
                row[908].into(),
                row[857..861].try_into().unwrap(),
                row[861..893].as_chunks::<8>().0.try_into().unwrap(),
                row[893..908].try_into().unwrap(),
            );
        }

        builder
            .when(phases[BLOCKS + 1].clone())
            .assert_zero(row[908]);
        let continuation: AB::Expr = phases[BLOCKS + 1..Self::ROWS - 1].iter().cloned().sum();
        builder.when_transition().when(continuation).assert_eq(
            next[908],
            extraction::carry::<AB::Expr>(row[893..908].try_into().unwrap()),
        );

        for value in &row[11..43] {
            builder.when(extracting.clone()).assert_zero(*value);
        }

        for value in &row[43..491] {
            builder.when(squeeze.clone()).assert_zero(*value);
        }

        for value in &row[791..] {
            builder.when(permuting.clone()).assert_zero(*value);
        }
    }
}

/// Complete reference conformance and invalid assignment boundaries.
#[cfg(test)]
mod tests {
    use super::{air::ScheduledHashAir, *};
    use crate::gadgets::RecipientHashAir;
    use crate::gadgets::poseidon2::ScheduledHash;
    use p3_air::{BaseAir, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;
    use p3_field::PrimeField64;
    use p3_matrix::dense::RowMajorMatrix;

    /// The production assignment matches the previously verified full recipient hash rows.
    #[test]
    fn scheduled_recipient_matches_existing_complete_relation() {
        let mut input = [Goldilocks::ZERO; 1636];
        input[64] = Goldilocks::ONE;
        input[1604..].fill(Goldilocks::from_u8(255));
        let reference = RecipientHashAir::new();
        let mut expected = vec![Goldilocks::ZERO; 64 * 909];
        reference.assign_trace(&input, &mut expected);

        let air = ScheduledHashAir::<35>::new(b"houseki/v1/recipient/kem-key", &[64, 4, 1568]);
        let mut actual = vec![Goldilocks::ZERO; 128 * 909];
        air.hash
            .assign(
                &[&input[..64], &input[64..68], &input[68..]],
                &mut actual,
                909,
            )
            .unwrap();
        assert!(actual[..52 * 909] == expected[..52 * 909]);

        let matrix = RowMajorMatrix::new(actual, air.width());
        assert!(
            check_all_constraints(&air, &matrix, &reference.public(&expected), Some(16)).is_ok()
        );
    }

    /// The final source byte is checked before any strided destination is overwritten.
    #[test]
    fn scheduled_assignment_preflights_all_sources_and_storage() {
        let hash =
            ScheduledHash::<35>::new(b"houseki/v1/recipient/kem-key", &[64, 4, 1568]).unwrap();
        let mut input = [Goldilocks::ZERO; 1636];
        input[1635] = Goldilocks::from_u16(256);
        let mut rows = vec![Goldilocks::NEG_ONE; 52 * 920];
        let parts = [&input[..64], &input[64..68], &input[68..]];
        assert_eq!(
            hash.assign(&parts, &mut rows, 920),
            Err(FramingError::InvalidByte)
        );
        assert!(rows.iter().all(|cell| *cell == Goldilocks::NEG_ONE));
        assert_eq!(
            hash.assign(&parts, &mut rows, 908),
            Err(FramingError::ShapeMismatch)
        );
        assert_eq!(
            hash.assign(&parts, &mut rows[..909], 920),
            Err(FramingError::ShapeMismatch)
        );
        assert_eq!(
            hash.assign(&parts[..2], &mut rows, 920),
            Err(FramingError::ShapeMismatch)
        );
        assert!(rows.iter().all(|cell| *cell == Goldilocks::NEG_ONE));
    }

    /// A second independently framed transcript matches the native note vector and preserves gaps.
    #[test]
    fn scheduled_note_hash_matches_native_vector_in_strided_storage() {
        let recipient =
            ScheduledHash::<35>::new(b"houseki/v1/recipient/kem-key", &[64, 4, 1568]).unwrap();
        let network = [Goldilocks::ZERO; 64];
        let version = [
            Goldilocks::ONE,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ];
        let key = [Goldilocks::ZERO; 1568];
        let mut first = vec![Goldilocks::ZERO; 52 * 909];
        recipient
            .assign(&[&network, &version, &key], &mut first, 909)
            .unwrap();
        let mut binding = [Goldilocks::ZERO; 64];
        recipient.copy_digest(&first, 909, &mut binding);

        let mut amount = [Goldilocks::ZERO; 16];
        amount[0] = Goldilocks::ONE;
        let blinding = [Goldilocks::ZERO; 32];
        let parts: [&[Goldilocks]; 6] =
            [&network, &version, &network, &binding, &amount, &blinding];
        let air =
            ScheduledHashAir::<7>::new(b"houseki/v1/note/commitment", &[64, 4, 64, 64, 16, 32]);
        let mut strided = vec![Goldilocks::NEG_ONE; 24 * 920];
        let (result, calls, bytes) =
            crate::test_allocator::measure(|| air.hash.assign(&parts, &mut strided, 920));
        result.unwrap();
        assert_eq!((calls, bytes), (0, 0));
        assert_eq!(air.hash.blocks().len(), 7);
        assert!(
            strided
                .as_chunks::<920>()
                .0
                .iter()
                .all(|row| row[909..].iter().all(|value| *value == Goldilocks::NEG_ONE))
        );

        let mut digest = [Goldilocks::ZERO; 64];
        air.hash.copy_digest(&strided, 920, &mut digest);
        let actual: String = digest
            .iter()
            .map(|value| format!("{:02x}", value.as_canonical_u64()))
            .collect();
        assert_eq!(
            actual,
            concat!(
                "67519504e20c7223a5068feae0c831bdfe180fcc11b6b597c5d8a4506d592c41",
                "decf8a6608538e3c875bcd61322d8a832f554417b2bc5a32f4cde0454adb20f0"
            )
        );

        let mut rows = vec![Goldilocks::ZERO; 128 * 909];
        for (destination, source) in rows
            .as_chunks_mut::<909>()
            .0
            .iter_mut()
            .zip(strided.as_chunks::<920>().0.iter())
        {
            destination.copy_from_slice(&source[..909]);
        }

        let mut public: Vec<_> = parts.into_iter().flatten().copied().collect();
        public.extend(digest);
        assert!(
            check_all_constraints(&air, &RowMajorMatrix::new(rows, 909), &public, Some(16)).is_ok()
        );
    }

    /// Source, state, sample, carry and inactive cells cannot be altered independently.
    #[test]
    fn scheduled_hash_rejects_mutated_internal_links_and_unused_cells() {
        let input = [Goldilocks::ZERO; 1636];
        let air = ScheduledHashAir::<35>::new(b"houseki/v1/recipient/kem-key", &[64, 4, 1568]);
        let mut rows = vec![Goldilocks::ZERO; 128 * 909];
        air.hash
            .assign(
                &[&input[..64], &input[64..68], &input[68..]],
                &mut rows,
                909,
            )
            .unwrap();
        let mut public = input.to_vec();
        for word in 0..16 {
            public.extend_from_slice(&rows[(36 + word) * 909 + 857..(36 + word) * 909 + 861]);
        }

        for (phase, cell) in [
            (0, 43),
            (17, 11),
            (34, 27),
            (35, 7),
            (36, 0),
            (37, 908),
            (51, 893),
            (0, 908),
            (35, 43),
            (36, 11),
            (127, 0),
        ] {
            let mut changed = rows.clone();
            changed[phase * 909 + cell] += Goldilocks::ONE;
            assert!(
                !check_all_constraints(&air, &RowMajorMatrix::new(changed, 909), &public, Some(1))
                    .is_ok(),
                "phase {phase}, cell {cell}"
            );
        }
    }
}
