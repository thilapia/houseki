//! Guarded transcript hashing under the fixed Poseidon2 profile.
//!
//! Part contents may be sensitive, while domains, counts and lengths remain public inputs
//! that determine framing, memory access boundaries and the number of permutations.

use crypto_bigint::{U64, U512, Word};
use zeroize::Zeroizing;

use super::{
    emit_frame,
    encoding::BytePacker,
    field::FieldElement,
    frame_length,
    permutation::permute,
    profile::{MODULUS, OUTPUT_ELEMENTS, RATE, WIDTH},
};
use crate::{CryptoFramingError, domain::Domain};

/// Hashes sensitive part bytes while retaining the result in guarded storage.
///
/// Measures the complete frame before absorbing its length and contents, using the same
/// registered domains and canonical part encoding as the public adapter.
///
/// Owned working buffers are cleared on return or unwinding, while borrowed inputs remain
/// the caller's responsibility and compiler or system copies cannot all be erased.
///
/// # Errors
///
/// Rejects an unrepresentable count, part length or total frame length before absorbing any
/// part contents, returning no digest on failure.
pub(crate) fn poseidon2_secret(
    domain: Domain,
    parts: &[&[u8]],
) -> Result<Zeroizing<[u8; 64]>, CryptoFramingError> {
    let length = frame_length(domain, parts)?;
    let mut sponge = Sponge {
        state: std::array::from_fn(|_| FieldElement::default()),
        used: 0,
    };
    let mut packer = BytePacker::default();
    packer.update(&length.to_le_bytes(), &mut |word| sponge.absorb(word));

    emit_frame(domain, parts, &mut |chunk| {
        packer.update(chunk, &mut |word| sponge.absorb(word));
    })?;
    packer.finish(&mut |word| sponge.absorb(word));

    Ok(sponge.finish())
}

/// Owned guarded field state for one additive sponge transcript.
struct Sponge {
    /// Rate and capacity elements whose individual guards clear their storage on drop.
    state: [FieldElement; WIDTH],

    /// Public count of occupied rate elements since the last permutation.
    used: usize,
}

impl Sponge {
    /// Adds a borrowed packed word or padding value and permutes each completed rate block.
    fn absorb(&mut self, word: &u64) {
        self.state[self.used] = self.state[self.used].add(&FieldElement::from_word(word));
        self.used += 1;
        if self.used == RATE {
            permute(&mut self.state);
            self.used = 0;
        }
    }

    /// Applies padding and extracts eleven samples while the caller retains guarded state.
    fn finish(&mut self) -> Zeroizing<[u8; 64]> {
        self.absorb(&1);
        while self.used != 0 {
            self.absorb(&0);
        }

        let mut values = Zeroizing::new([0; OUTPUT_ELEMENTS]);
        for (value, field) in values[..RATE].iter_mut().zip(&self.state[..RATE]) {
            *value = *field.canonical_word();
        }

        permute(&mut self.state);
        for (value, field) in values[RATE..].iter_mut().zip(&self.state) {
            *value = *field.canonical_word();
        }

        extract_digest(&values)
    }
}

/// Extracts the low 512 bits of the integer represented by canonical base p samples.
///
/// Wrapping integer arithmetic discards carries beyond 512 bits without reducing the result
/// in the Goldilocks field, and the caller retains ownership of the borrowed samples.
fn extract_digest(values: &[u64; OUTPUT_ELEMENTS]) -> Zeroizing<[u8; 64]> {
    let mut integer = Zeroizing::new(U512::ZERO);
    for value in values.iter().rev() {
        let product = Zeroizing::new(integer.wrapping_mul(&U64::from_u64(MODULUS)));
        let sample = Zeroizing::new(U512::from_u64(*value));
        *integer = product.wrapping_add(&sample);
    }

    let mut digest = Zeroizing::new([0; 64]);
    for (output, word) in digest
        .as_chunks_mut::<{ size_of::<Word>() }>()
        .0
        .iter_mut()
        .zip(integer.as_words())
    {
        let bytes = Zeroizing::new(word.to_le_bytes());
        output.copy_from_slice(bytes.as_ref());
    }

    digest
}

/// Complete transcript agreement and independent integer extraction vectors.
#[cfg(test)]
mod tests {
    use super::*;

    /// Checks both paths across packing and rate boundaries with empty and varied parts.
    #[test]
    fn guarded_transcripts_match_the_public_adapter() {
        for length in (0..=110).chain([256, 512]) {
            let bytes: Vec<_> = (0..length).map(|i| (i as u8).wrapping_mul(179)).collect();
            let split = length / 2;
            let parts: &[&[u8]] = &[&bytes[..split], &[], &bytes[split..]];
            for domain in [Domain::RecipientKemKey, Domain::NoteEncryptionCore] {
                let actual = poseidon2_secret(domain, parts).unwrap();
                assert_eq!(*actual, super::super::poseidon2(domain, parts).unwrap());
            }
        }

        let empty = poseidon2_secret(Domain::RecipientKemKey, &[]).unwrap();
        let empty_part = poseidon2_secret(Domain::RecipientKemKey, &[&[]]).unwrap();

        assert_ne!(*empty, *empty_part);
        assert_eq!(
            *empty,
            super::super::poseidon2(Domain::RecipientKemKey, &[]).unwrap()
        );
    }

    /// Checks canonical extraction against independently calculated carries and truncation.
    #[test]
    fn extraction_matches_independent_integer_vectors() {
        // Python sum(x[i] * p**i for i in range(11)) % 2**512, little endian.
        for (values, expected) in [
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
        ] {
            let actual = extract_digest(&values);
            let hex: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();

            assert_eq!(hex, expected);
        }

        assert_eq!(*extract_digest(&[0; 11]), [0; 64]);
    }
}
