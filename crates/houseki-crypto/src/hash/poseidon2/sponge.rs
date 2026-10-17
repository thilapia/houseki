//! Public field state for one fixed additive Poseidon2 sponge.

use super::{
    encoding::extract_digest,
    profile::{OUTPUT_ELEMENTS, RATE, WIDTH, permute},
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Fresh additive sponge state for one public transcript.
pub(super) struct Sponge {
    /// Permutation state containing rate and capacity elements.
    pub(super) state: [Goldilocks; WIDTH],

    /// Rate elements occupied since the last permutation.
    pub(super) used: usize,
}

impl Sponge {
    /// Adds a packed word or padding value and permutes each completed rate block.
    pub(super) fn absorb(&mut self, word: u64) {
        // Only seven byte words and the field padding values 0 and 1 enter.
        debug_assert!(word < (1 << 56));

        self.state[self.used] += Goldilocks::new(word);
        self.used += 1;
        if self.used == RATE {
            permute(&mut self.state);
            self.used = 0;
        }
    }

    /// Appends mandatory field padding, squeezes eleven elements and extracts the digest.
    pub(super) fn finish(mut self) -> [u8; 64] {
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
