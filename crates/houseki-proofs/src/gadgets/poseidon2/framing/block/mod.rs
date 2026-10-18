//! Fixed metadata and bounded witness storage for one absorption block.

#[cfg(test)]
mod air;

#[cfg(test)]
pub(crate) use air::BlockAir;

use super::{Frame, FramingError, PACKED_BYTES, byte::Byte};
#[cfg(any(test, feature = "prover"))]
use crate::gadgets::assign_byte;
use crate::gadgets::eval_byte;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
#[cfg(any(test, feature = "prover"))]
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Number of words absorbed by the fixed application sponge.
const WORDS: usize = crate::gadgets::poseidon2::profile::RATE;

/// Byte cells in one complete absorption block, including fixed zero extension.
const BYTES: usize = WORDS * PACKED_BYTES;

/// One trusted block of seven packed words in the application transcript.
///
/// Owns only public metadata, with storage independent of the total input length.
pub(crate) struct Block {
    /// Fixed bytes and input coordinates, with zero bytes after the transcript ends.
    positions: [Byte; BYTES],

    /// Full ordered part lengths used to validate borrowed assignment inputs.
    lengths: &'static [usize],

    /// Local word containing the mandatory field one, if it occurs in this block.
    padding: Option<usize>,
}

impl Block {
    /// Selects metadata only after checking the index against the complete padded frame.
    pub(super) fn new(frame: &Frame, index: usize) -> Result<Self, FramingError> {
        let start = index
            .checked_mul(WORDS)
            .filter(|start| *start < frame.padded_words)
            .ok_or(FramingError::BlockIndexOutOfBounds)?;
        let mut positions = [Byte::Constant(0); BYTES];
        if start < frame.packed_words {
            // A word containing transcript bytes starts before the checked frame byte length.
            for (position, byte) in positions
                .iter_mut()
                .zip(frame.bytes().skip(start * PACKED_BYTES))
            {
                *position = byte;
            }
        }

        Ok(Self {
            positions,
            lengths: frame.lengths,
            padding: (start..start + WORDS)
                .contains(&frame.packed_words)
                .then(|| frame.packed_words - start),
        })
    }

    /// Yields each variable byte's local cell, ordered part index and offset within that part.
    ///
    /// Consumers must bind these cells to the corresponding semantic inputs, select every block
    /// in order and link packed words into the sponge with state continuity.
    pub(crate) fn input_positions(&self) -> impl Iterator<Item = (usize, usize, usize)> + '_ {
        self.positions
            .iter()
            .enumerate()
            .filter_map(|(local, byte)| match byte {
                Byte::Constant(_) => None,
                Byte::Input { part, offset } => Some((local, *part, *offset)),
            })
    }

    /// Constrains byte ranges, immutable metadata, partial-word zeros and exact field padding.
    ///
    /// All 49 byte cells and decompositions are constrained, including constant and unused slots.
    ///
    /// Each packed integer is below the field modulus, so equality establishes integer packing.
    ///
    /// This component does not enforce the consumer's input links, block order or sponge state.
    pub(crate) fn eval<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        values: &[AB::Var; BYTES],
        bits: &[[AB::Var; 8]; BYTES],
        words: &[AB::Var; WORDS],
    ) {
        for (index, position) in self.positions.iter().enumerate() {
            eval_byte(builder, values[index], &bits[index]);
            if let Byte::Constant(value) = position {
                builder.assert_eq(values[index], AB::Expr::from_u8(*value));
            }
        }

        for (index, bytes) in values.as_chunks::<PACKED_BYTES>().0.iter().enumerate() {
            let mut word = AB::Expr::from_bool(self.padding == Some(index));
            for (offset, byte) in bytes.iter().enumerate() {
                word += *byte * Goldilocks::from_u64(1 << (8 * offset));
            }

            builder.assert_eq(words[index], word);
        }
    }

    /// Assigns one block into borrowed byte, bit and packed-word destinations.
    ///
    /// Does not allocate or retain private inputs, and guards temporary integer words.
    ///
    /// The caller owns cleanup of all supplied cells and must independently evaluate constraints.
    ///
    /// # Errors
    ///
    /// Checks all part lengths before reading values and returns [`FramingError::ShapeMismatch`]
    /// if they differ from the complete frame layout.
    ///
    /// Returns [`FramingError::InvalidByte`] if any input selected by this block exceeds 255.
    ///
    /// Inputs belonging only to other blocks are not read, and every destination is unchanged
    /// on either error.
    #[cfg(any(test, feature = "prover"))]
    pub(crate) fn assign(
        &self,
        parts: &[&[Goldilocks]],
        values: &mut [Goldilocks; BYTES],
        bits: &mut [[Goldilocks; 8]; BYTES],
        words: &mut [Goldilocks; WORDS],
    ) -> Result<(), FramingError> {
        if !parts
            .iter()
            .map(|part| part.len())
            .eq(self.lengths.iter().copied())
        {
            return Err(FramingError::ShapeMismatch);
        }

        for (_, part, offset) in self.input_positions() {
            let value = Zeroizing::new(parts[part][offset].as_canonical_u64());
            if *value > u64::from(u8::MAX) {
                return Err(FramingError::InvalidByte);
            }
        }

        for (index, position) in self.positions.iter().enumerate() {
            values[index] = match position {
                Byte::Constant(value) => Goldilocks::from_u8(*value),
                Byte::Input { part, offset } => parts[*part][*offset],
            };

            assign_byte(&values[index], &mut bits[index])
                .expect("selected frame bytes were validated");
        }

        for (index, bytes) in values.as_chunks::<PACKED_BYTES>().0.iter().enumerate() {
            let mut word = Zeroizing::new(u64::from(self.padding == Some(index)));
            for (offset, byte) in bytes.iter().enumerate() {
                let value = Zeroizing::new(byte.as_canonical_u64());
                *word += *value << (8 * offset);
            }

            words[index] = Goldilocks::from_u64(*word);
        }

        Ok(())
    }
}

/// Independent transcript vectors and bounded assignment behavior.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gadgets::{
            BlockAir, HashFrame,
            poseidon2::{extraction, sponge},
        },
        test_allocator,
    };
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_matrix::dense::RowMajorMatrix;

    /// Registered label shared with the independent native recipient-binding vectors.
    const DOMAIN: &[u8] = b"houseki/v1/recipient/kem-key";

    /// Checks an independently supplied row while following its claimed public packed words.
    fn evaluate(air: &BlockAir, row: &[Goldilocks; 448]) -> ConstraintReport {
        let matrix = RowMajorMatrix::new(row.to_vec(), 448);

        check_all_constraints(air, &matrix, &row[441..], Some(8))
    }

    /// Complete key-sized framing preserves native network, suite and all public key bytes.
    #[test]
    fn full_recipient_inputs_match_independent_native_digests() {
        let network = std::array::from_fn::<_, 64, _>(Goldilocks::from_usize);
        let suite = [
            Goldilocks::ONE,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ];
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
            let mut key = [Goldilocks::ZERO; 1568];
            key[1536..].fill(Goldilocks::from_u8(seed));
            let mut blocks = Vec::new();
            for index in 0..35 {
                let air = BlockAir::new(DOMAIN, &[64, 4, 1568], index);
                let mut row = [Goldilocks::NEG_ONE; 448];
                air.assign_row(&[&network, &suite, &key], &mut row).unwrap();

                assert!(evaluate(&air, &row).is_ok(), "block {index}");
                blocks.push(row[441..].try_into().unwrap());
            }

            let mut samples = [Goldilocks::ZERO; 11];
            sponge::assign(
                &blocks,
                &mut [[Goldilocks::ZERO; 16]; 36],
                &mut [[Goldilocks::ZERO; 150]; 36],
                &mut [[Goldilocks::ZERO; 150]; 36],
                &mut samples,
            )
            .unwrap();
            let mut digest = [Goldilocks::ZERO; 64];
            extraction::assign(
                &samples,
                &mut [[Goldilocks::ZERO; 74]; 11],
                &mut digest,
                &mut [[Goldilocks::ZERO; 8]; 64],
                &mut [[Goldilocks::ZERO; 15]; 16],
            );
            let actual: String = digest
                .iter()
                .map(|byte| format!("{:02x}", byte.as_canonical_u64()))
                .collect();

            assert_eq!(actual, expected);
        }
    }

    /// Exposes every real-sized source byte once and in transcript order without metadata slots.
    #[test]
    fn source_positions_cover_each_part_without_gaps_or_duplicates() {
        let frame = HashFrame::new(DOMAIN, &[64, 4, 1568]).unwrap();
        let mut positions = Vec::new();
        for index in 0..35 {
            let block = frame.block(index).unwrap();
            for (local, part, offset) in block.input_positions() {
                let expected_global = match part {
                    0 => 50 + offset,
                    1 => 122 + offset,
                    2 => 134 + offset,
                    _ => panic!("unexpected input part"),
                };

                assert_eq!(index * 49 + local, expected_global);
                positions.push((part, offset));
            }
        }

        let expected: Vec<_> = [64, 4, 1568]
            .into_iter()
            .enumerate()
            .flat_map(|(part, length)| (0..length).map(move |offset| (part, offset)))
            .collect();

        assert_eq!(positions, expected);
        assert!(matches!(
            frame.block(35),
            Err(FramingError::BlockIndexOutOfBounds)
        ));
        assert!(matches!(
            frame.block(usize::MAX),
            Err(FramingError::BlockIndexOutOfBounds)
        ));
    }

    /// Every packing residue agrees with the existing full-frame API and retains mandatory padding.
    #[test]
    fn packing_residues_and_exact_rate_keep_the_complete_padding_block() {
        for lengths in [
            &[0][..],
            &[1],
            &[2],
            &[3],
            &[4],
            &[5],
            &[6],
            &[7],
            &[41],
            &[42],
            &[48],
            &[49],
        ] {
            let frame = HashFrame::new(DOMAIN, lengths).unwrap();
            let input = vec![Goldilocks::from_u8(0xa3); lengths[0]];
            let mut expected = vec![Goldilocks::ZERO; frame.word_len()];
            frame
                .assign(
                    &[&input],
                    &mut [&mut vec![[Goldilocks::ZERO; 8]; input.len()]],
                    &mut expected,
                )
                .unwrap();
            let mut actual = Vec::new();
            for index in 0..frame.word_len() / 7 {
                let air = BlockAir::new(DOMAIN, lengths, index);
                let mut row = [Goldilocks::NEG_ONE; 448];
                air.assign_row(&[&input], &mut row).unwrap();

                assert!(evaluate(&air, &row).is_ok());
                actual.extend_from_slice(&row[441..]);
            }

            assert_eq!(actual, expected);
            if lengths[0] == 48 {
                assert_eq!(
                    &actual[14..],
                    &[
                        Goldilocks::ONE,
                        Goldilocks::ZERO,
                        Goldilocks::ZERO,
                        Goldilocks::ZERO,
                        Goldilocks::ZERO,
                        Goldilocks::ZERO,
                        Goldilocks::ZERO
                    ]
                );
            }
        }
    }

    /// Every byte, bit and word is constrained in header, mixed-part and final padded blocks.
    #[test]
    fn every_block_cell_is_constrained_without_external_input_links() {
        for index in [0, 2, 34] {
            let air = BlockAir::new(DOMAIN, &[64, 4, 1568], index);
            let mut original = [Goldilocks::NEG_ONE; 448];
            air.assign_row(
                &[
                    &[Goldilocks::from_u8(17); 64],
                    &[Goldilocks::ONE; 4],
                    &[Goldilocks::from_u8(31); 1568],
                ],
                &mut original,
            )
            .unwrap();

            assert!(evaluate(&air, &original).is_ok());
            for cell in 0..448 {
                let mut row = original;
                row[cell] += Goldilocks::ONE;

                assert!(!evaluate(&air, &row).is_ok(), "block {index}, cell {cell}");
            }
        }
    }

    /// Corrected bits and words cannot replace fixed metadata, zero extension or padding bytes.
    #[test]
    fn recomputed_constant_forgery_still_fails_its_metadata_constraint() {
        for index in [0, 2, 34] {
            let air = BlockAir::new(DOMAIN, &[64, 4, 1568], index);
            let mut original = [Goldilocks::NEG_ONE; 448];
            air.assign_row(
                &[
                    &[Goldilocks::ZERO; 64],
                    &[Goldilocks::ONE; 4],
                    &[Goldilocks::ZERO; 1568],
                ],
                &mut original,
            )
            .unwrap();
            for (local, position) in air.block.positions.iter().enumerate() {
                if let Byte::Constant(value) = position {
                    let mut row = original;
                    row[local] = Goldilocks::from_u8(value.wrapping_add(1));
                    let byte = row[local];
                    assign_byte(
                        &byte,
                        (&mut row[49 + local * 8..49 + (local + 1) * 8])
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap();
                    row[441 + local / 7] +=
                        (byte - original[local]) * Goldilocks::from_u64(1 << (8 * (local % 7)));

                    assert_eq!(
                        evaluate(&air, &row).failures.len(),
                        1,
                        "block {index}, byte {local}"
                    );
                }
            }
        }
    }

    /// Matching byte reconstruction and packed words cannot admit a non-Boolean high bit.
    #[test]
    fn recomputed_out_of_range_byte_fails_its_boolean_constraint() {
        let air = BlockAir::new(DOMAIN, &[64, 4, 1568], 2);
        let mut row = [Goldilocks::NEG_ONE; 448];
        air.assign_row(
            &[
                &[Goldilocks::ZERO; 64],
                &[Goldilocks::ONE; 4],
                &[Goldilocks::ZERO; 1568],
            ],
            &mut row,
        )
        .unwrap();

        row[0] = Goldilocks::from_u16(256);
        row[56] = Goldilocks::TWO;
        row[441] += Goldilocks::from_u16(256);

        assert_eq!(evaluate(&air, &row).failures.len(), 1);
    }

    /// Shape checks precede byte reads, failures are atomic and unselected blocks are not read.
    #[test]
    fn assignment_validates_only_selected_bytes_without_allocating() {
        let frame = HashFrame::new(DOMAIN, &[64, 4, 1568]).unwrap();
        let mut network = [Goldilocks::ZERO; 64];
        let suite = [Goldilocks::ONE; 4];
        let mut key = [Goldilocks::ZERO; 1568];
        key[1567] = Goldilocks::from_u16(256);
        let mut values = [Goldilocks::NEG_ONE; 49];
        let mut bits = [[Goldilocks::NEG_ONE; 8]; 49];
        let mut words = [Goldilocks::NEG_ONE; 7];
        let (result, calls, bytes) = test_allocator::measure(|| {
            frame.block(2).unwrap().assign(
                &[&network, &suite, &key],
                &mut values,
                &mut bits,
                &mut words,
            )
        });

        assert_eq!((result, calls, bytes), (Ok(()), 0, 0));

        let original = (values, bits, words);
        network[48] = Goldilocks::from_u16(256);
        let block = frame.block(2).unwrap();
        let result = block.assign(&[&network, &suite], &mut values, &mut bits, &mut words);

        assert_eq!(result, Err(FramingError::ShapeMismatch));
        assert_eq!((values, bits, words), original);

        let result = block.assign(
            &[&network, &suite, &key],
            &mut values,
            &mut bits,
            &mut words,
        );

        assert_eq!(result, Err(FramingError::InvalidByte));
        assert_eq!((values, bits, words), original);

        let result = frame.block(34).unwrap().assign(
            &[&network, &suite, &key],
            &mut values,
            &mut bits,
            &mut words,
        );

        assert_eq!(result, Err(FramingError::InvalidByte));
        assert_eq!((values, bits, words), original);
    }

    /// Preserves empty parts, split length prefixes, partial words and field padding.
    #[test]
    fn blocks_preserve_independent_complete_transcript_vector() {
        let frame = HashFrame::new(b"houseki/v1/recipient/kem-key", &[0, 2, 1]).unwrap();
        let parts: [&[Goldilocks]; 3] = [
            &[],
            &[Goldilocks::from_u8(b'a'), Goldilocks::from_u8(b'b')],
            &[Goldilocks::from_u8(b'c')],
        ];
        let mut actual = Vec::new();
        for index in 0..2 {
            let block = frame.block(index).unwrap();
            let mut values = [Goldilocks::NEG_ONE; 49];
            let mut bits = [[Goldilocks::NEG_ONE; 8]; 49];
            let mut words = [Goldilocks::NEG_ONE; 7];
            block
                .assign(&parts, &mut values, &mut bits, &mut words)
                .unwrap();
            actual.extend(words.map(|word| word.as_canonical_u64()));
        }

        assert_eq!(
            actual,
            [
                0x0000000000003d,
                0x73756f68001c00,
                0x2f31762f696b65,
                0x65697069636572,
                0x2d6d656b2f746e,
                0x0000000379656b,
                0x00000000000000,
                0x00000000000200,
                0x00000162610000,
                0x00630000000000,
                1,
                0,
                0,
                0,
            ]
        );
    }
}
