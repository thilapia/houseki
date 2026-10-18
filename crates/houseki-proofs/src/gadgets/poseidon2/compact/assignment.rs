//! Guarded assignment directly into a caller's strided hash work cells.

use super::CompactHash;
use crate::gadgets::{
    Scratch, assign_field_bytes,
    poseidon2::{extraction, framing::FramingError, permutation},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

impl<const BLOCKS: usize> CompactHash<BLOCKS> {
    /// Assigns the complete operation without allocating or retaining another witness owner.
    ///
    /// # Errors
    ///
    /// Shape errors precede invalid input bytes and every failure leaves destinations unchanged.
    ///
    /// The caller owns cleanup of all input and destination cells, including stride gaps which
    /// this operation never writes.
    pub(crate) fn assign(
        &self,
        parts: &[&[Goldilocks]],
        rows: &mut [Goldilocks],
        stride: usize,
    ) -> Result<(), FramingError> {
        let required = (Self::ROWS - 1)
            .checked_mul(stride)
            .and_then(|start| start.checked_add(Self::WIDTH));
        if stride < Self::WIDTH
            || required.is_none_or(|length| length > rows.len())
            || !parts
                .iter()
                .map(|part| part.len())
                .eq(self.lengths.iter().copied())
        {
            return Err(FramingError::ShapeMismatch);
        }

        for part in parts {
            for value in *part {
                let word = Zeroizing::new(value.as_canonical_u64());
                if *word > 255 {
                    return Err(FramingError::InvalidByte);
                }
            }
        }

        for phase in 0..Self::ROWS {
            rows[phase * stride..phase * stride + Self::WIDTH].fill(Goldilocks::ZERO);
        }

        let mut state = Scratch::<16>::default();
        let mut samples = Scratch::<11>::default();
        for phase in 0..=BLOCKS {
            let row = &mut rows[phase * stride..phase * stride + Self::WIDTH];
            if phase < BLOCKS {
                let (values, rest) = row[43..491].split_at_mut(49);
                let (bits, words) = rest.split_at_mut(392);
                self.blocks[phase]
                    .assign(
                        parts,
                        values.try_into().unwrap(),
                        bits.as_chunks_mut::<8>().0.try_into().unwrap(),
                        words.try_into().unwrap(),
                    )
                    .expect("complete hash inputs were validated");
            }

            row[11..27].copy_from_slice(&state[..]);
            for coordinate in 0..7 {
                state[coordinate] += row[484 + coordinate];
            }

            let (prefix, helpers) = row.split_at_mut(491);
            let (cubes, powers) = helpers[..300].split_at_mut(150);
            permutation::assign(
                &state,
                cubes.try_into().unwrap(),
                powers.try_into().unwrap(),
                (&mut prefix[27..43]).try_into().unwrap(),
            );
            state.copy_from_slice(&prefix[27..43]);
            if phase + 1 == BLOCKS {
                samples[..7].copy_from_slice(&state[..7]);
            }

            if phase == BLOCKS {
                samples[7..].copy_from_slice(&state[..4]);
            }
        }

        for phase in 0..Self::ROWS {
            rows[phase * stride..phase * stride + 11].copy_from_slice(&samples[..]);
        }

        let mut incoming = Zeroizing::new(0_i64);
        for column in 0..16 {
            let phase = BLOCKS + 1 + column;
            let row = &mut rows[phase * stride..phase * stride + Self::WIDTH];
            for (sample, value) in samples.iter().enumerate() {
                let encoded = Zeroizing::new(value.as_canonical_u64());
                for byte in 0..8 {
                    row[43 + sample * 8 + byte] =
                        Goldilocks::from_u64((*encoded >> (8 * byte)) & 255);
                }
            }

            if column < 11 {
                let (prefix, auxiliary) = row.split_at_mut(131);
                let (bits, helpers) = auxiliary[..66].split_at_mut(64);
                let (is_max, inverse) = helpers.split_at_mut(1);
                assign_field_bytes(
                    &samples[column],
                    (&mut prefix[43 + column * 8..51 + column * 8])
                        .try_into()
                        .unwrap(),
                    bits.as_chunks_mut::<8>().0.try_into().unwrap(),
                    &mut is_max[0],
                    &mut inverse[0],
                );
            }

            row[248] = Goldilocks::from_i64(*incoming);
            let (bytes, rest) = row[197..248].split_at_mut(4);
            let (bits, carry) = rest.split_at_mut(32);
            extraction::assign_word(
                &samples,
                column,
                &mut incoming,
                bytes.try_into().unwrap(),
                bits.as_chunks_mut::<8>().0.try_into().unwrap(),
                carry.try_into().unwrap(),
            );
        }

        Ok(())
    }

    /// Copies the final digest into an existing owner without returning private intermediate arrays.
    ///
    /// The caller supplies the same valid strided layout used by assignment and owns cleanup of
    /// both buffers, with no allocation or retained reference in this operation.
    pub(crate) fn copy_digest(
        &self,
        rows: &[Goldilocks],
        stride: usize,
        destination: &mut [Goldilocks; 64],
    ) {
        for (column, word) in destination.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let start = (BLOCKS + 1 + column) * stride + 197;
            word.copy_from_slice(&rows[start..start + 4]);
        }
    }
}
