//! Byte packing and integer extraction for the fixed Poseidon2 profile.

use super::profile::{MODULUS, OUTPUT_ELEMENTS, PACKED_BYTES};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use zeroize::{Zeroize, Zeroizing};

/// Streams bytes as seven byte little endian words across chunk boundaries.
///
/// Finishing zero fills only a final partial word.
///
/// The enclosing transcript supplies the byte length, and the sponge adds field padding.
///
/// Pending bytes and emitted words stay in guarded storage, with the sink borrowing each word
/// only for the duration of its call.
#[derive(Default)]
pub(super) struct BytePacker {
    /// Pending bytes of the next little endian word.
    buffer: Zeroizing<[u8; PACKED_BYTES]>,

    /// Number of initialized pending bytes.
    used: usize,
}

impl BytePacker {
    /// Emits full seven byte words while retaining a partial word across calls.
    pub(super) fn update(&mut self, mut bytes: &[u8], emit: &mut impl FnMut(&u64)) {
        while !bytes.is_empty() {
            let take = bytes.len().min(PACKED_BYTES - self.used);
            self.buffer[self.used..self.used + take].copy_from_slice(&bytes[..take]);
            self.used += take;

            bytes = &bytes[take..];
            if self.used == PACKED_BYTES {
                self.emit_word(emit);
            }
        }
    }

    /// Emits a pending partial word with zero padding and consumes the packer.
    pub(super) fn finish(mut self, emit: &mut impl FnMut(&u64)) {
        if self.used != 0 {
            self.emit_word(emit);
        }
    }

    /// Clears the pending bytes before lending their zero extended word to the sink.
    fn emit_word(&mut self, emit: &mut impl FnMut(&u64)) {
        let mut word = Zeroizing::new([0; 8]);
        word[..self.used].copy_from_slice(&self.buffer[..self.used]);

        let value = Zeroizing::new(u64::from_le_bytes(*word));
        self.buffer.zeroize();
        self.used = 0;

        emit(&value);
    }
}

/// Converts canonical field values to the low 512 bits of their base p integer.
///
/// Extraction is lossy and retains the low 512 bits without reducing them in the field.
pub(super) fn extract_digest(values: [Goldilocks; OUTPUT_ELEMENTS]) -> [u8; 64] {
    // Horner evaluation in Z/(2^512).
    // Canonical samples and each carry are below p, so a u64 limb times p plus carry always
    // fits in a u128.
    let mut limbs = [0_u64; 8];
    for value in values.iter().rev() {
        let mut carry = u128::from(value.as_canonical_u64());
        for limb in &mut limbs {
            let product = u128::from(*limb) * u128::from(MODULUS) + carry;
            *limb = product as u64; // Deliberately retain only the low limb.
            carry = product >> 64;
        }
        // Discard the carry beyond limb seven, as required by mod 2^512.
    }

    let mut digest = [0; 64];
    for (bytes, limb) in digest.as_chunks_mut::<8>().0.iter_mut().zip(limbs) {
        bytes.copy_from_slice(&limb.to_le_bytes());
    }

    digest
}

/// Packing boundaries and independent integer extraction vectors.
#[cfg(test)]
mod tests {
    use super::super::profile::MODULUS;
    use super::{BytePacker, Goldilocks, extract_digest};

    /// Checks that emitted bytes are cleared before the packer begins another word.
    #[test]
    fn emitted_bytes_do_not_remain_in_the_pending_buffer() {
        let mut packer = BytePacker::default();
        packer.update(&[0xa5; 7], &mut |_| {});

        assert_eq!(&packer.buffer[..], &[0; 7]);
        assert_eq!(packer.used, 0);
    }

    /// Checks that a panicking sink cannot leave the emitted word in the pending buffer.
    #[test]
    fn pending_bytes_are_cleared_before_a_sink_unwinds() {
        let mut packer = BytePacker::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            packer.update(&[0xa5; 7], &mut |_| panic!("fixture sink failure"));
        }));

        assert!(result.is_err());
        assert_eq!(&packer.buffer[..], &[0; 7]);
        assert_eq!(packer.used, 0);
    }

    /// Checks that input chunk boundaries do not alter packed words.
    #[test]
    fn packing_preserves_bytes_across_every_chunk_boundary() {
        let bytes: Vec<_> = (1..=20).collect();
        for chunk_size in 1..=20 {
            let mut result = Vec::new();
            let mut packer = BytePacker::default();
            for chunk in bytes.chunks(chunk_size) {
                packer.update(&[], &mut |x| result.push(*x));
                packer.update(chunk, &mut |x| result.push(*x));
            }

            packer.finish(&mut |x| result.push(*x));

            assert_eq!(
                result,
                [
                    0x0007_0605_0403_0201,
                    0x000e_0d0c_0b0a_0908,
                    0x0000_1413_1211_100f
                ]
            );
        }
    }

    /// Checks word counts for empty, exact and partial inputs.
    #[test]
    fn packing_empty_exact_and_partial_words_does_not_add_extra_words() {
        for (input, expected) in [
            (vec![], vec![]),
            (vec![0xff; 7], vec![0x00ff_ffff_ffff_ffff]),
            (vec![0xff; 8], vec![0x00ff_ffff_ffff_ffff, 0xff]),
            (vec![0; 14], vec![0, 0]),
        ] {
            let mut result = Vec::new();
            let mut packer = BytePacker::default();
            packer.update(&input, &mut |x| result.push(*x));
            packer.finish(&mut |x| result.push(*x));

            assert_eq!(result, expected);
            assert!(result.into_iter().all(|x| x < (1 << 56)));
        }
    }

    /// Checks extraction against independent carry and truncation vectors.
    #[test]
    fn extraction_matches_independent_integer_arithmetic_with_carries_and_truncation() {
        // Python sum(x[i] * p**i for i in range(11)) % 2**512, little endian.
        let vectors = [
            (
                [MODULUS - 1; 11],
                concat!(
                    "00000000f5ffffff41000000edfeffff6f0300001bf7ffff34130000aedcffff",
                    "1238000071b2ffff035e0000cb9bffff035e000071b2ffff12380000aedcffff"
                ),
            ),
            (
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                concat!(
                    "370000007ffeffffa80600009aeaffffa7360000048dffff92cc0000bfc7feff",
                    "3a9d01002e23feff56e10100d556fefffd4701002524ffff087f00008cc1ffff"
                ),
            ),
            (
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, MODULUS - 1],
                concat!(
                    "00000000ffffffff0a000000bfffffff08010000c7fcffff1208000032efffff",
                    "a51d00000fd3ffff0a3b000069bcffff96430000f5c4fffff02c00005ae2ffff"
                ),
            ),
        ];

        for (values, expected) in vectors {
            let actual = extract_digest(Goldilocks::new_array(values));
            let hex: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();

            assert_eq!(hex, expected);
        }

        assert_eq!(extract_digest(Goldilocks::new_array([0; 11])), [0; 64]);
        assert_eq!(
            extract_digest(Goldilocks::new_array([MODULUS; 11])),
            [0; 64]
        );
    }
}
