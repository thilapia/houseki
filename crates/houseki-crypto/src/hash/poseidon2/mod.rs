//! Houseki's fixed Poseidon2 transcript adapters.
//!
//! Public and guarded hashing share framing and packing while retaining separate arithmetic
//! paths for their field state and integer extraction.

mod encoding;
mod field;
mod guarded;
mod permutation;
mod profile;

pub(crate) use guarded::poseidon2_secret;

use crate::{
    CryptoFramingError,
    domain::{Domain, Frame},
};
use encoding::{BytePacker, extract_digest};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use profile::{OUTPUT_ELEMENTS, RATE, WIDTH, permute};

/// Hashes canonical public parts under a registered domain.
///
/// Measures the common frame, then streams its u64 byte length and contents through packing and
/// the additive sponge.
///
/// The same immutable parts supply both passes.
///
/// Returns a framing error without a digest if a count or length is unrepresentable.
pub(crate) fn poseidon2(domain: Domain, parts: &[&[u8]]) -> Result<[u8; 64], CryptoFramingError> {
    let length = frame_length(domain, parts)?;
    let mut sponge = Sponge {
        state: [Goldilocks::ZERO; WIDTH],
        used: 0,
    };
    let mut packer = BytePacker::default();
    packer.update(&length.to_le_bytes(), &mut |word| sponge.absorb(*word));

    emit_frame(domain, parts, &mut |chunk| {
        packer.update(chunk, &mut |word| sponge.absorb(*word));
    })?;
    packer.finish(&mut |word| sponge.absorb(*word));

    Ok(sponge.finish())
}

/// Measures the complete frame without reading part contents or retaining their bytes.
///
/// Returns a framing error when a count, part length or total length cannot be represented.
fn frame_length(domain: Domain, parts: &[&[u8]]) -> Result<u64, CryptoFramingError> {
    let mut length = Ok(0_u64);
    emit_frame(domain, parts, &mut |chunk| {
        length = length.and_then(|length| add_frame_length(length, chunk.len()));
    })?;
    length
}

/// Streams the registered domain and ordered parts through the common codec.
///
/// Returns an error if part counts or lengths cannot be represented.
fn emit_frame(
    domain: Domain,
    parts: &[&[u8]],
    sink: &mut dyn FnMut(&[u8]),
) -> Result<(), CryptoFramingError> {
    let count = u32::try_from(parts.len()).map_err(|_| CryptoFramingError::TooManyParts)?;
    let mut frame = Frame::new(domain, count, sink);

    for part in parts {
        frame.part(part)?;
    }

    frame.finish()
}

/// Accumulates one chunk length or rejects overflow of the u64 frame prefix.
fn add_frame_length(length: u64, chunk_length: usize) -> Result<u64, CryptoFramingError> {
    let chunk_length = u64::try_from(chunk_length).map_err(|_| CryptoFramingError::FrameTooLong)?;
    length
        .checked_add(chunk_length)
        .ok_or(CryptoFramingError::FrameTooLong)
}

/// Fresh additive sponge state for one public transcript.
struct Sponge {
    /// Permutation state containing rate and capacity elements.
    state: [Goldilocks; WIDTH],

    /// Rate elements occupied since the last permutation.
    used: usize,
}

impl Sponge {
    /// Adds a packed word or padding value and permutes each completed rate block.
    fn absorb(&mut self, word: u64) {
        // Only seven-byte words and the field padding values 0 and 1 enter.
        debug_assert!(word < (1 << 56));
        self.state[self.used] += Goldilocks::new(word);
        self.used += 1;
        if self.used == RATE {
            permute(&mut self.state);
            self.used = 0;
        }
    }

    /// Appends mandatory field padding, squeezes eleven elements and extracts the digest.
    fn finish(mut self) -> [u8; 64] {
        // Always append one, including at an exact rate boundary.
        self.absorb(1);
        while self.used != 0 {
            self.absorb(0);
        }

        let mut values = [Goldilocks::ZERO; OUTPUT_ELEMENTS];
        values[..RATE].copy_from_slice(&self.state[..RATE]);
        permute(&mut self.state);
        values[RATE..].copy_from_slice(&self.state[..OUTPUT_ELEMENTS - RATE]);
        extract_digest(values)
    }
}

/// Complete sponge vectors, domain separation and frame length limits.
#[cfg(test)]
mod tests {
    use super::{CryptoFramingError, Domain, add_frame_length, poseidon2};

    /// Checks complete sponge vectors around packing and padding boundaries.
    #[test]
    fn sponge_matches_independent_vectors_at_packing_and_padding_boundaries() {
        // Independent Python field arithmetic using the pinned upstream constants, checked
        // against its permutation KAT first.
        // Includes the u64 frame-length prefix, seven-byte words, mandatory field padding, two
        // squeeze reads and base-p extraction.
        // Length 48 gives exactly fourteen input words and requires a complete extra padding
        // block.
        for (length, expected) in [
            (
                0,
                "9eaca7771384bbd29d7a6ab689ebf558b05a7a0d1afbfa9dd1924798123f1c0db97518cea39f4c3b72ce77930b93db258477e3d25db9e21e46e090ae612dc301",
            ),
            (
                6,
                "76735931774e8ccd1202ca3b6e4ae65f31d1a740a1ab91cecc5eea82b0fd5cfb0d2782962a79ee58a6f20f96ba46c8f789ede12bbba55f5e3e326f83e5abb790",
            ),
            (
                7,
                "2ac400e18bd3d3ae9fae7ad903651cc85cbd5cc6d15f7ec9610e1a506279d881c48a1846763b6b3aaab643c50c620cd9cf346adc3f5fb3fde1451709a5679919",
            ),
            (
                41,
                "64a6b40193460ab442b2e0ac100be2faae99bde90c22a972cafd2b9d5a487c8254f297df6c2e6b99360a3cb8ccf4251b6aec816eeb20f1b5cdf46fa2982fb108",
            ),
            (
                42,
                "33b72595242b6afb62847735e088af243fa005dad58f9e4e905e7a629097ba0f82303bf721952d3a8b23e93a0318fd7783635217f11f11df5ce69a03a1594711",
            ),
            (
                48,
                "70614b29d19856c773d669fba3347e74ec8ccdbcd851e2c80bcd3a10cfc69e10a5aa7bd65ca7abf602ad9e75cc6a7e7a8058d9bb8d3f9c13e05c122ab1e3a194",
            ),
            (
                49,
                "200b94fdc2b1c02df7405af28a898ad0a28c34f8b10997974d9f61a4f6a4e98fb54f06d0e92714d617259b1c3e82a7872ce015aca9c8b480ee291c89d16e1fc0",
            ),
        ] {
            let bytes = vec![0xa3; length];
            for digest in [
                poseidon2(Domain::RecipientKemKey, &[&bytes]).unwrap(),
                *super::guarded::poseidon2_secret(Domain::RecipientKemKey, &[&bytes]).unwrap(),
            ] {
                let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
                assert_eq!(actual, expected, "length {length}");
            }
        }
    }

    /// Checks separation of domains, ordered parts and trailing zero bytes.
    #[test]
    fn domain_and_framed_part_boundaries_remain_distinct() {
        let parts: &[&[&[u8]]] = &[
            &[],
            &[b""],
            &[b"", b""],
            &[b"ab", b"c"],
            &[b"a", b"bc"],
            &[b"c", b"ab"],
            &[b"abc"],
            &[b"abc", b"abc"],
            &[b"abc\0"],
        ];

        let mut digests = Vec::new();
        for domain in [Domain::RecipientKemKey, Domain::NoteEncryptionCore] {
            for parts in parts {
                let digest = poseidon2(domain, parts).unwrap();
                assert!(!digests.contains(&digest));
                digests.push(digest);
            }
        }
    }

    /// Checks frame length overflow using synthetic counts.
    #[test]
    fn complete_frame_length_is_checked_without_allocating_large_inputs() {
        assert_eq!(add_frame_length(u64::MAX, 0), Ok(u64::MAX));
        assert_eq!(add_frame_length(u64::MAX - 8, 8), Ok(u64::MAX));
        assert_eq!(
            add_frame_length(u64::MAX, 1),
            Err(CryptoFramingError::FrameTooLong)
        );
        assert_eq!(
            add_frame_length(u64::MAX - 7, 8),
            Err(CryptoFramingError::FrameTooLong)
        );
    }
}
