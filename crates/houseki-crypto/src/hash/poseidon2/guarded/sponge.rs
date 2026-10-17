//! Guarded field state and sampling for one fixed Poseidon2 sponge.

use super::extract_digest;
use crate::hash::poseidon2::{
    field::FieldElement,
    permutation::permute,
    profile::{OUTPUT_ELEMENTS, RATE, WIDTH},
};
use zeroize::Zeroizing;

/// Owned guarded field state for one additive sponge transcript.
pub(super) struct Sponge {
    /// Rate and capacity elements whose individual guards clear their storage on drop.
    pub(super) state: [FieldElement; WIDTH],

    /// Public count of occupied rate elements since the last permutation.
    pub(super) used: usize,
}

impl Sponge {
    /// Adds a borrowed packed word or padding value and permutes each completed rate block.
    pub(super) fn absorb(&mut self, word: &u64) {
        self.state[self.used] = self.state[self.used].add(&FieldElement::from_word(word));
        self.used += 1;
        if self.used == RATE {
            permute(&mut self.state);
            self.used = 0;
        }
    }

    /// Applies padding and extracts eleven samples while the caller retains guarded state.
    pub(super) fn finish(&mut self) -> Zeroizing<[u8; 64]> {
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
