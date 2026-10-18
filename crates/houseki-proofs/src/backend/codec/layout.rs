//! Trusted dimensions for canonical hiding proof encoding and decoding.

use super::CodecError;
use crate::{
    backend::config::{EXTENSION_DEGREE, LOG_BLOWUP, QUERIES, SALT_ELEMENTS},
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

    /// Bounds canonical bytes for every possible valid binary multiproof frontier.
    ///
    /// All scalar, salt and vector dimensions are exact.
    ///
    /// Frontier maxima are summed independently,
    /// which remains conservative when batches and rounds share the same sampled query indices.
    pub(crate) fn encoded_upper_bound(self) -> Result<usize, CodecError> {
        self.validate()?;
        let rounds = self.degree_bits() as u128;
        let chunks = self.quotient_chunks as u128;
        let width = self.width as u128;
        let points = self.points(1) as u128;
        let extension = EXTENSION_DEGREE as u128;
        let queries = QUERIES as u128;
        let salts = SALT_ELEMENTS as u128;
        let extension_bytes = extension * 8;
        let mut bytes = super::HEADER_BYTES as u128 + 8 + 3 * 64;
        bytes += points * width * extension_bytes + (chunks + 1) * extension * extension_bytes;
        bytes += (1 + points + chunks) * extension * extension_bytes;
        bytes += rounds * 64;
        bytes += queries * 8 * (width + extension + (1 + chunks) * 2 * extension);
        bytes += queries * salts * 8 * (2 + chunks);
        bytes += 3 * (4 + 64 * frontier_maximum(self.input_height()) as u128);
        bytes += rounds * queries * (extension_bytes + salts * 8);
        for round in 0..self.degree_bits() {
            bytes += 4 + 64 * frontier_maximum(self.input_height() - round - 1) as u128;
        }

        bytes += extension_bytes;
        usize::try_from(bytes).map_err(|_| CodecError::InvalidShape)
    }

    /// Bounds all decoded vector payloads and nested headers on supported 32-bit and 64-bit targets.
    ///
    /// Scalar and digest storage is covered by encoded bytes.
    ///
    /// Additional 24-byte vector headers,
    /// 72-byte opening records and the omitted zero grinding vector cover every Reader allocation.
    pub(crate) fn decoded_upper_bound(self) -> Result<usize, CodecError> {
        let encoded = self.encoded_upper_bound()? as u128;
        let chunks = self.quotient_chunks as u128;
        let points = self.points(1) as u128;
        let rounds = self.degree_bits() as u128;
        let queries = QUERIES as u128;
        let nested = 24 * (3 * chunks + 6 + points)
            + 216
            + 144 * queries
            + 48 * queries * (2 + chunks)
            + rounds * (104 + 72 * queries);
        usize::try_from(encoded + nested).map_err(|_| CodecError::InvalidShape)
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

/// Maximum frontier among at most 128 distinct leaves in a binary tree of the trusted height.
///
/// The query bound is a power of two.
///
/// Filling that many root branches leaves at most one missing
/// sibling per selected branch at each deeper level.
///
/// Short trees saturate at half their leaves.
pub(super) fn frontier_maximum(height: usize) -> usize {
    let selected = QUERIES.min(1 << (height - 1));
    selected * (height - selected.ilog2() as usize)
}

/// Shape-independent byte arithmetic checked against the largest completed payment geometry.
#[cfg(test)]
mod tests {
    use super::*;

    /// Every randomized valid frontier fits the unchanged complete proof cap at the priority width.
    #[test]
    fn payment_layout_structural_byte_bounds() {
        for (log_rows, expected) in [(11, 1_892_172), (12, 1_989_520), (13, 2_095_060)] {
            let layout = Layout {
                log_rows,
                width: 1185,
                quotient_chunks: 8,
                main_next: true,
            };
            assert_eq!(layout.encoded_upper_bound().unwrap(), expected);
            assert!(expected <= MAX_PROOF_BYTES);
            assert!(layout.decoded_upper_bound().unwrap() <= super::super::MAX_DECODED_BYTES);
        }

        let excessive = Layout {
            log_rows: 13,
            width: 1231,
            quotient_chunks: 8,
            main_next: true,
        };
        assert!(excessive.encoded_upper_bound().unwrap() > MAX_PROOF_BYTES);
    }

    /// An independent split recurrence maximizes every feasible number of queried leaves.
    #[test]
    fn frontier_bound_matches_exhaustive_count_recurrence() {
        let mut previous = vec![0; 2];
        for height in 1..=32 {
            let child_capacity = previous.len() - 1;
            let capacity = QUERIES.min(2 * child_capacity);
            let mut next = vec![0; capacity + 1];
            for (count, maximum) in next.iter_mut().enumerate().skip(1) {
                for left in 0..=count.min(child_capacity) {
                    let right = count - left;
                    if right > child_capacity {
                        continue;
                    }

                    let frontier =
                        previous[left] + previous[right] + usize::from(left == 0 || right == 0);
                    *maximum = (*maximum).max(frontier);
                }
            }

            assert_eq!(frontier_maximum(height), *next.iter().max().unwrap());
            previous = next;
        }
    }
}
