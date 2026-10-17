//! Trusted dimensions for canonical hiding proof encoding and decoding.

use super::CodecError;
use crate::{
    backend::config::{EXTENSION_DEGREE, LOG_BLOWUP},
    profile::MAX_PROOF_BYTES,
};

/// Trusted shape metadata for the fixed backend without preprocessed commitments.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Layout {
    /// Logarithm of the original trace height before hiding interleaving.
    pub(crate) log_rows: usize,

    /// Exact number of main trace columns.
    pub(crate) width: usize,

    /// Exact power of two count of randomized quotient chunks.
    pub(crate) quotient_chunks: usize,

    /// Whether the AIR requires a second main trace opening.
    pub(crate) main_next: bool,
}

impl Layout {
    /// Rejects unsupported geometry before any payload driven loop or allocation.
    pub(super) fn validate(self) -> Result<(), CodecError> {
        if !(9..=28).contains(&self.log_rows)
            || self.width == 0
            || self.width > MAX_PROOF_BYTES / 8
            || self.quotient_chunks < 2
            || !self.quotient_chunks.is_power_of_two()
            || self.quotient_chunks > MAX_PROOF_BYTES / 8
        {
            return Err(CodecError::InvalidShape);
        }

        Ok(())
    }

    /// Returns the interleaved commitment degree and binary FRI round count.
    pub(super) fn degree_bits(self) -> usize {
        self.log_rows + 1
    }

    /// Returns the maximum binary input commitment height after low degree extension.
    pub(super) fn input_height(self) -> usize {
        self.degree_bits() + LOG_BLOWUP
    }

    /// Returns the exact matrix count in a random, trace or quotient opening batch.
    pub(super) fn matrices(self, batch: usize) -> usize {
        if batch == 2 { self.quotient_chunks } else { 1 }
    }

    /// Returns the exact OOD point count for one opening batch.
    pub(super) fn points(self, batch: usize) -> usize {
        if batch == 1 && self.main_next { 2 } else { 1 }
    }

    /// Returns the committed width including the three hiding codewords.
    pub(super) fn committed_width(self, batch: usize) -> usize {
        if batch == 1 {
            self.width + EXTENSION_DEGREE
        } else {
            2 * EXTENSION_DEGREE
        }
    }
}
