//! Fixed byte and carry geometry for the eleven sample integer extraction.

/// Byte count of the retained low 512 bits.
pub(super) const DIGEST_BYTES: usize = 64;

/// Number of base 2^32 output words.
pub(super) const WORDS: usize = DIGEST_BYTES / 4;

/// Cells for eight canonical bytes, their bits and two canonicality helpers.
pub(super) const ENCODING: usize = 74;

/// Boolean cells encoding each biased signed carry.
pub(super) const CARRY_BITS: usize = 15;

/// Bias mapping fifteen unsigned bits to the interval from -16384 through 16383.
pub(super) const BIAS: i64 = 1 << (CARRY_BITS - 1);

/// Integer radix of each output word, independent of the proof field.
pub(super) const RADIX: i64 = 1 << 32;
