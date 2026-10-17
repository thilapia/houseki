//! Exact length framing, seven byte packing and mandatory rate padding.

#[cfg(test)]
mod air;
mod byte;
mod error;

#[cfg(test)]
pub(crate) use air::FramingAir;
pub(crate) use error::FramingError;

use super::profile::RATE;
#[cfg(any(test, feature = "prover"))]
use crate::gadgets::assign_byte;
use crate::gadgets::eval_byte;
use byte::Byte;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
#[cfg(any(test, feature = "prover"))]
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Bytes per packed word, keeping its integer value below the field modulus.
const PACKED_BYTES: usize = 7;

/// Trusted fixed metadata for an application hash input, independent of witness values.
///
/// The consuming circuit selects the registered domain and exact ordered part lengths from its
/// immutable relation, rather than deriving them from a witness or proof header.
///
/// This type borrows only public metadata and owns no private inputs or trace storage.
pub(crate) struct Frame {
    /// Registered label selected by the consuming circuit.
    domain: &'static [u8],

    /// Exact byte lengths of ordered parts selected by the circuit.
    lengths: &'static [usize],

    /// Complete framed byte length excluding its own eight byte prefix.
    frame_length: u64,

    /// Total number of private or public input byte cells across all parts.
    input_bytes: usize,

    /// Words occupied by the length prefix and frame before field padding.
    packed_words: usize,

    /// Complete output block length after mandatory field padding.
    padded_words: usize,
}

impl Frame {
    /// Validates the public metadata without allocating or reading private inputs.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::LayoutTooLarge`] if the label exceeds u16, the part count exceeds
    /// u32, or any part length, frame length or padded layout exceeds its integer representation.
    ///
    /// Representability does not authorize a resource budget, which the circuit must bound
    /// before allocating its trace.
    pub(crate) fn new(
        domain: &'static [u8],
        lengths: &'static [usize],
    ) -> Result<Self, FramingError> {
        let label_length = u16::try_from(domain.len()).map_err(|_| FramingError::LayoutTooLarge)?;
        u32::try_from(lengths.len()).map_err(|_| FramingError::LayoutTooLarge)?;
        let mut frame_length = u64::from(label_length) + 6;
        let mut input_bytes = 0_usize;
        for length in lengths {
            let part_length = u64::try_from(*length).map_err(|_| FramingError::LayoutTooLarge)?;
            frame_length = frame_length
                .checked_add(8)
                .and_then(|total| total.checked_add(part_length))
                .ok_or(FramingError::LayoutTooLarge)?;
            input_bytes = input_bytes
                .checked_add(*length)
                .ok_or(FramingError::LayoutTooLarge)?;
        }

        let bytes = usize::try_from(frame_length)
            .ok()
            .and_then(|length| length.checked_add(8))
            .ok_or(FramingError::LayoutTooLarge)?;
        let packed_words = bytes.div_ceil(PACKED_BYTES);
        let padded_words = packed_words
            .checked_add(1)
            .and_then(|length| length.checked_next_multiple_of(RATE))
            .ok_or(FramingError::LayoutTooLarge)?;

        Ok(Self {
            domain,
            lengths,
            frame_length,
            input_bytes,
            packed_words,
            padded_words,
        })
    }

    /// Returns the number of part bytes represented in the layout.
    pub(crate) fn input_len(&self) -> usize {
        self.input_bytes
    }

    /// Returns the packed words including mandatory field padding to the rate boundary.
    pub(crate) fn word_len(&self) -> usize {
        self.padded_words
    }

    /// Constrains every input byte and links it to the exact padded packed words.
    ///
    /// Fixed metadata appears as constants and every input byte receives its own range check.
    ///
    /// Each reconstructed word is at most 2^56 minus one, below the field modulus, so its field
    /// equality establishes the exact packed integer including zero extension of a partial word.
    ///
    /// Padding is always a field one followed by zeros to the next block of seven words, including
    /// a complete new block when packed input fills the previous one.
    ///
    /// The circuit must link these words into its additive sponge and its inputs to the intended
    /// statement and witness relations.
    ///
    /// # Panics
    ///
    /// Panics before emitting constraints if any borrowed shape differs from the fixed layout,
    /// which indicates a circuit implementation error rather than invalid witness values.
    pub(crate) fn eval<AB: AirBuilder<F = Goldilocks>>(
        &self,
        builder: &mut AB,
        parts: &[&[AB::Var]],
        bits: &[&[[AB::Var; 8]]],
        words: &[AB::Var],
    ) {
        assert!(
            self.matches(parts, bits.iter().map(|part| part.len()), words.len()),
            "hash frame shapes must match the fixed circuit layout"
        );
        for (part, decompositions) in parts.iter().zip(bits) {
            for (value, decomposition) in part.iter().zip(*decompositions) {
                eval_byte(builder, *value, decomposition);
            }
        }

        let mut reconstructed = AB::Expr::ZERO;
        let mut position = 0;
        let mut used = 0;
        for byte in self.bytes(parts) {
            let value = match byte {
                Byte::Constant(value) => AB::Expr::from_u8(value),
                Byte::Input(value) => (*value).into(),
            };

            reconstructed += value * Goldilocks::from_u64(1 << (8 * used));
            used += 1;
            if used == PACKED_BYTES {
                builder.assert_eq(words[position], reconstructed);
                reconstructed = AB::Expr::ZERO;
                used = 0;
                position += 1;
            }
        }

        if used != 0 {
            builder.assert_eq(words[position], reconstructed);
        }

        builder.assert_one(words[self.packed_words]);
        for word in &words[self.packed_words + 1..] {
            builder.assert_zero(*word);
        }
    }

    /// Assigns every bit and padded word after validating shapes and input byte ranges.
    ///
    /// No allocation occurs, inputs remain borrowed, and integer temporaries are wiped on return.
    ///
    /// The caller owns cleanup of input and destination cells and must evaluate the constraints
    /// independently of this honest assignment.
    ///
    /// # Errors
    ///
    /// Checks all part, bit and output lengths before reading input values and returns
    /// [`FramingError::ShapeMismatch`] if any differ from this layout.
    ///
    /// Returns [`FramingError::InvalidByte`] if any input's canonical value exceeds 255, with
    /// every destination cell unchanged on either error.
    #[cfg(any(test, feature = "prover"))]
    pub(crate) fn assign(
        &self,
        parts: &[&[Goldilocks]],
        bits: &mut [&mut [[Goldilocks; 8]]],
        words: &mut [Goldilocks],
    ) -> Result<(), FramingError> {
        if !self.matches(parts, bits.iter().map(|part| part.len()), words.len()) {
            return Err(FramingError::ShapeMismatch);
        }

        for value in parts.iter().flat_map(|part| part.iter()) {
            let word = Zeroizing::new(value.as_canonical_u64());
            if *word > u64::from(u8::MAX) {
                return Err(FramingError::InvalidByte);
            }
        }

        for (part, decompositions) in parts.iter().zip(bits) {
            for (value, decomposition) in part.iter().zip(decompositions.iter_mut()) {
                assign_byte(value, decomposition).expect("all frame bytes were validated");
            }
        }

        let mut word = Zeroizing::new(0_u64);
        let mut position = 0;
        let mut used = 0;
        for byte in self.bytes(parts) {
            let value = Zeroizing::new(match byte {
                Byte::Constant(value) => u64::from(value),
                Byte::Input(value) => value.as_canonical_u64(),
            });

            *word += *value << (8 * used);
            used += 1;
            if used == PACKED_BYTES {
                words[position] = Goldilocks::from_u64(*word);
                *word = 0;
                used = 0;
                position += 1;
            }
        }

        if used != 0 {
            words[position] = Goldilocks::from_u64(*word);
        }

        words[self.packed_words] = Goldilocks::ONE;
        words[self.packed_words + 1..].fill(Goldilocks::ZERO);

        Ok(())
    }

    /// Checks all borrowed shapes using only public lengths, without inspecting input cells.
    fn matches<V>(
        &self,
        parts: &[&[V]],
        bit_lengths: impl Iterator<Item = usize>,
        words: usize,
    ) -> bool {
        parts
            .iter()
            .map(|part| part.len())
            .eq(self.lengths.iter().copied())
            && bit_lengths.eq(self.lengths.iter().copied())
            && words == self.padded_words
    }

    /// Streams public prefix bytes and borrowed input cells in exact native transcript order.
    fn bytes<'a, V>(&'a self, parts: &'a [&'a [V]]) -> impl Iterator<Item = Byte<'a, V>> {
        self.frame_length
            .to_le_bytes()
            .into_iter()
            .map(Byte::Constant)
            .chain(
                (self.domain.len() as u16)
                    .to_le_bytes()
                    .into_iter()
                    .map(Byte::Constant),
            )
            .chain(self.domain.iter().copied().map(Byte::Constant))
            .chain(
                (self.lengths.len() as u32)
                    .to_le_bytes()
                    .into_iter()
                    .map(Byte::Constant),
            )
            .chain(self.lengths.iter().zip(parts).flat_map(|(length, part)| {
                (*length as u64)
                    .to_le_bytes()
                    .into_iter()
                    .map(Byte::Constant)
                    .chain(part.iter().map(Byte::Input))
            }))
    }
}

/// Independent framing vectors, malicious cells and atomic assignment failures.
#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::{BaseAir, check_all_constraints};
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_matrix::dense::RowMajorMatrix;

    /// Registered native domain used by the independent framing vectors.
    const DOMAIN: &[u8] = b"houseki/v1/recipient/kem-key";

    /// Assigns a public fixture into sentinel-filled storage to detect incomplete writes.
    fn assigned(air: &FramingAir, bytes: &[u8]) -> Vec<Goldilocks> {
        let mut row = vec![Goldilocks::NEG_ONE; air.width()];
        air.assign_row(
            &bytes
                .iter()
                .copied()
                .map(Goldilocks::from_u8)
                .collect::<Vec<_>>(),
            &mut row,
        )
        .unwrap();

        row
    }

    /// Evaluates arbitrary trace cells using their current words as public outputs.
    fn valid(air: &FramingAir, row: &[Goldilocks]) -> bool {
        let matrix = RowMajorMatrix::new(row.repeat(2), air.width());
        check_all_constraints(air, &matrix, &row[air.frame.input_len() * 9..], Some(32)).is_ok()
    }

    /// Compares the complete transcript with hand-checkable native framing and packing vectors.
    #[test]
    fn exact_frames_match_independent_words() {
        for (lengths, bytes, expected) in [
            (
                &[][..],
                &b""[..],
                &[
                    0x00000000000022,
                    0x73756f68001c00,
                    0x2f31762f696b65,
                    0x65697069636572,
                    0x2d6d656b2f746e,
                    0x0000000079656b,
                    1,
                ][..],
            ),
            (
                &[0, 2, 1][..],
                &b"abc"[..],
                &[
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
                ][..],
            ),
            (
                &[8][..],
                &[1, 2, 3, 4, 5, 6, 7, 8][..],
                &[
                    0x00000000000032,
                    0x73756f68001c00,
                    0x2f31762f696b65,
                    0x65697069636572,
                    0x2d6d656b2f746e,
                    0x0000000179656b,
                    0x00000000000008,
                    0x06050403020100,
                    0x00000000000807,
                    1,
                    0,
                    0,
                    0,
                    0,
                ][..],
            ),
        ] {
            let air = FramingAir::new(DOMAIN, lengths);
            let row = assigned(&air, bytes);
            let words: Vec<_> = row[bytes.len() * 9..]
                .iter()
                .map(|word| word.as_canonical_u64())
                .collect();

            assert_eq!(words, expected);
            assert!(valid(&air, &row));
        }
    }

    /// Every packing residue and both sides of a rate boundary have mandatory padding.
    #[test]
    fn packing_and_rate_boundaries_preserve_all_bytes() {
        for lengths in [
            &[0][..],
            &[1],
            &[2],
            &[3],
            &[4],
            &[5],
            &[6],
            &[7],
            &[8],
            &[40],
            &[41],
            &[42],
            &[47],
            &[48],
            &[49],
            &[50],
            &[55],
        ] {
            let air = FramingAir::new(DOMAIN, lengths);
            let bytes = vec![0xa3; lengths[0]];
            let row = assigned(&air, &bytes);
            // Native header and one part length occupy 50 bytes including the outer length.
            let packed = (50 + bytes.len()).div_ceil(7);
            let padded = (packed + 1).next_multiple_of(7);
            let words = &row[bytes.len() * 9..];

            assert_eq!(words.len(), padded);
            assert_eq!(words[packed], Goldilocks::ONE);
            assert!(
                words[packed + 1..]
                    .iter()
                    .all(|word| *word == Goldilocks::ZERO)
            );
            assert!(
                words[..packed]
                    .iter()
                    .all(|word| word.as_canonical_u64() < 1 << 56)
            );
            assert!(valid(&air, &row));

            for index in packed..padded {
                let mut changed = row.clone();
                changed[bytes.len() * 9 + index] += Goldilocks::ONE;

                assert!(!valid(&air, &changed));
            }
        }
    }

    /// Every byte, bit, prefix-containing word and padding word is independently linked.
    #[test]
    fn every_cell_is_constrained_without_public_input_links() {
        let air = FramingAir::new(DOMAIN, &[0, 2, 1]);
        let row = assigned(&air, b"abc");
        for index in 0..row.len() {
            let mut changed = row.clone();
            changed[index] += Goldilocks::ONE;

            assert!(!valid(&air, &changed), "cell {index}");
        }
    }

    /// Updating a byte and its valid bits cannot preserve an unchanged packed output.
    #[test]
    fn every_packed_input_position_is_linked() {
        let air = FramingAir::new(DOMAIN, &[48]);
        let row = assigned(&air, &[0; 48]);
        for index in 0..48 {
            let mut changed = row.clone();
            changed[index] = Goldilocks::ONE;
            changed[48 + index * 8] = Goldilocks::ONE;

            assert!(!valid(&air, &changed));
        }
    }

    /// Every byte of the outer length, domain, count and part length is fixed by the layout.
    #[test]
    fn every_framing_prefix_byte_is_fixed() {
        let air = FramingAir::new(DOMAIN, &[8]);
        let row = assigned(&air, &[0; 8]);
        for offset in 0..50 {
            let mut changed = row.clone();
            changed[72 + offset / 7] += Goldilocks::from_u64(1 << (8 * (offset % 7)));

            assert!(!valid(&air, &changed));
        }
    }

    /// A field-valued bit cannot bypass byte ranges even with matching packing and reconstruction.
    #[test]
    fn modular_byte_alias_cannot_pass_packing() {
        let air = FramingAir::new(DOMAIN, &[8]);
        let mut row = assigned(&air, &[0; 8]);
        row[0] = Goldilocks::from_u16(256);
        row[8 + 7] = Goldilocks::TWO;
        row[72 + 7] += Goldilocks::from_u32(256 * 256);

        assert!(!valid(&air, &row));
    }

    /// High zero-extension bytes in the final packed word cannot retain hidden data.
    #[test]
    fn partial_word_high_bytes_are_zero() {
        let air = FramingAir::new(DOMAIN, &[8]);
        let row = assigned(&air, &[0; 8]);
        for index in 2..7 {
            let mut changed = row.clone();
            changed[72 + 8] += Goldilocks::from_u64(1 << (8 * index));

            assert!(!valid(&air, &changed));
        }
    }

    /// Different part lengths, counts and domains cannot reuse the same packed transcript.
    #[test]
    fn structure_and_common_prefixes_are_distinct() {
        let cases = [
            (DOMAIN, &[][..], &b""[..]),
            (DOMAIN, &[0][..], &b""[..]),
            (DOMAIN, &[0, 0][..], &b""[..]),
            (DOMAIN, &[2, 1][..], &b"abc"[..]),
            (DOMAIN, &[1, 2][..], &b"abc"[..]),
            (DOMAIN, &[3][..], &b"abc"[..]),
            (DOMAIN, &[4][..], &b"abc\0"[..]),
            (&b"houseki/v1/note/commitment"[..], &[3][..], &b"abc"[..]),
        ];
        let words: Vec<_> = cases
            .iter()
            .map(|(domain, lengths, bytes)| {
                let air = FramingAir::new(domain, lengths);
                let row = assigned(&air, bytes);

                row[bytes.len() * 9..].to_vec()
            })
            .collect();

        for (index, value) in words.iter().enumerate() {
            for other in &words[index + 1..] {
                assert_ne!(value, other);
            }
        }
    }

    /// Correct byte decompositions cannot reuse words from a different fixed part structure.
    #[test]
    fn wrong_lengths_cannot_reuse_a_common_prefix() {
        let air = FramingAir::new(DOMAIN, &[2, 1]);
        let other = FramingAir::new(DOMAIN, &[1, 2]);
        let mut row = assigned(&air, b"abc");
        let changed = assigned(&other, b"abc");
        row[27..].copy_from_slice(&changed[27..]);

        assert!(!valid(&air, &row));

        let air = FramingAir::new(DOMAIN, &[3]);
        let other = FramingAir::new(DOMAIN, &[4]);
        let mut row = assigned(&air, b"abc");
        let changed = assigned(&other, b"abc\0");
        row[27..].copy_from_slice(&changed[36..]);

        assert!(!valid(&air, &row));
    }

    /// High integer-prefix bytes survive packing without truncation to the low byte.
    #[test]
    fn label_count_and_part_length_prefixes_preserve_high_bytes() {
        for (domain, lengths, input, outer, label, count, part) in [
            (
                DOMAIN,
                &[258][..],
                vec![0x5a; 258],
                [44, 1, 0, 0, 0, 0, 0, 0],
                [28, 0],
                [1, 0, 0, 0],
                Some([2, 1, 0, 0, 0, 0, 0, 0]),
            ),
            (
                DOMAIN,
                &[0; 256][..],
                vec![],
                [34, 8, 0, 0, 0, 0, 0, 0],
                [28, 0],
                [0, 1, 0, 0],
                Some([0; 8]),
            ),
            (
                &[b'a'; 256][..],
                &[][..],
                vec![],
                [6, 1, 0, 0, 0, 0, 0, 0],
                [0, 1],
                [0; 4],
                None,
            ),
        ] {
            let air = FramingAir::new(domain, lengths);
            let row = assigned(&air, &input);
            let bytes: Vec<_> = row[input.len() * 9..]
                .iter()
                .flat_map(|word| {
                    let bytes = word.as_canonical_u64().to_le_bytes();

                    bytes[..7].to_vec()
                })
                .collect();

            assert_eq!(bytes[..8], outer);
            assert_eq!(bytes[8..10], label);
            assert_eq!(bytes[10..10 + domain.len()], *domain);
            let count_offset = 10 + domain.len();
            assert_eq!(bytes[count_offset..count_offset + 4], count);
            if let Some(expected) = part {
                assert_eq!(bytes[count_offset + 4..count_offset + 12], expected);
            }

            assert!(valid(&air, &row));
        }
    }

    /// Incorrect shapes take precedence and every invalid byte preserves all destination cells.
    #[test]
    fn rejected_assignment_is_atomic() {
        let frame = Frame::new(DOMAIN, &[2, 1]).unwrap();
        for invalid in 0..3 {
            let mut values = [Goldilocks::ZERO; 3];
            values[invalid] = Goldilocks::NEG_ONE;
            let mut bits = [[Goldilocks::NEG_ONE; 8]; 3];
            let mut words = vec![Goldilocks::NEG_ONE; frame.word_len()];
            let (first, second) = bits.split_at_mut(2);
            let result = frame.assign(
                &[&values[..2], &values[2..]],
                &mut [first, second],
                &mut words,
            );

            assert_eq!(result, Err(FramingError::InvalidByte));
            assert_eq!(bits, [[Goldilocks::NEG_ONE; 8]; 3]);
            assert!(words.iter().all(|word| *word == Goldilocks::NEG_ONE));
        }

        let invalid = [Goldilocks::NEG_ONE; 3];
        let mut bits = [[Goldilocks::NEG_ONE; 8]; 3];
        let mut words = vec![Goldilocks::NEG_ONE; frame.word_len()];
        assert_eq!(
            frame.assign(&[&invalid], &mut [&mut bits], &mut words),
            Err(FramingError::ShapeMismatch)
        );
        assert_eq!(bits, [[Goldilocks::NEG_ONE; 8]; 3]);
        assert!(words.iter().all(|word| *word == Goldilocks::NEG_ONE));
    }

    /// Missing, excess or mispartitioned input and auxiliary slices reject before any writes.
    #[test]
    fn all_shape_mismatches_precede_input_validation() {
        let frame = Frame::new(DOMAIN, &[2, 1]).unwrap();
        for (part_lengths, bit_lengths, word_length) in [
            (&[1, 2][..], &[2, 1][..], 14),
            (&[2][..], &[2, 1][..], 14),
            (&[2, 1, 0][..], &[2, 1][..], 14),
            (&[2, 1][..], &[1, 2][..], 14),
            (&[2, 1][..], &[2][..], 14),
            (&[2, 1][..], &[2, 1, 0][..], 14),
            (&[2, 1][..], &[2, 1][..], 13),
            (&[2, 1][..], &[2, 1][..], 15),
        ] {
            let input: Vec<_> = part_lengths
                .iter()
                .map(|length| vec![Goldilocks::NEG_ONE; *length])
                .collect();
            let mut bits: Vec<_> = bit_lengths
                .iter()
                .map(|length| vec![[Goldilocks::NEG_ONE; 8]; *length])
                .collect();
            let mut words = vec![Goldilocks::NEG_ONE; word_length];
            let result = frame.assign(
                &input.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                &mut bits.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
                &mut words,
            );

            assert_eq!(result, Err(FramingError::ShapeMismatch));
            assert!(
                bits.iter()
                    .flatten()
                    .flatten()
                    .all(|value| *value == Goldilocks::NEG_ONE)
            );
            assert!(words.iter().all(|value| *value == Goldilocks::NEG_ONE));
        }
    }

    /// Synthetic sizes reject overflow without allocating their claimed private payloads.
    #[test]
    fn excessive_layouts_are_rejected_before_storage() {
        assert!(matches!(
            Frame::new(DOMAIN, &[usize::MAX]),
            Err(FramingError::LayoutTooLarge)
        ));
        assert!(matches!(
            Frame::new(DOMAIN, &[usize::MAX / 2, usize::MAX / 2]),
            Err(FramingError::LayoutTooLarge)
        ));
        assert!(matches!(
            Frame::new(&[b'a'; 65536], &[]),
            Err(FramingError::LayoutTooLarge)
        ));
        assert!(Frame::new(DOMAIN, &[0]).is_ok());
    }
}
