//! One ranged output word and its bounded signed carry in the integer extraction.

use super::{
    coefficients::coefficient,
    profile::{BIAS, CARRY_BITS, ENCODING, RADIX, WORDS},
};
#[cfg(any(test, feature = "prover"))]
use crate::gadgets::assign_bytes;
use crate::gadgets::{eval_bytes, poseidon2::profile::SAMPLES};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
#[cfg(any(test, feature = "prover"))]
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Reconstructs a signed carry from its independently constrained biased bits.
pub(in crate::gadgets::poseidon2) fn carry<R: PrimeCharacteristicRing + From<Goldilocks>>(
    bits: &[impl Copy + Into<R>; CARRY_BITS],
) -> R {
    let mut result = R::from(Goldilocks::from_i64(-BIAS));
    for (index, bit) in bits.iter().enumerate() {
        result += (*bit).into() * R::from(Goldilocks::from_u32(1 << index));
    }

    result
}

/// Constrains one base 2^32 word without discarding its final outgoing carry equation.
///
/// The caller constrains all sample encodings canonically and the incoming carry to the same
/// signed range, or supplies zero for the first word.
///
/// Positive coefficient sums are at most 12827 and negative magnitudes at most 12826, so every
/// equation's residual has magnitude below 2^48 and cannot wrap in Goldilocks.
///
/// Returns the ranged outgoing carry for the next word, including the carry above bit 511
/// which the complete extraction intentionally discards after constraining it.
pub(in crate::gadgets::poseidon2) fn eval<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    encodings: &[[AB::Var; ENCODING]; SAMPLES],
    column: usize,
    incoming: AB::Expr,
    bytes: &[AB::Var; 4],
    bits: &[[AB::Var; 8]; 4],
    carry_bits: &[AB::Var; CARRY_BITS],
) -> AB::Expr {
    assert!(column < WORDS);
    eval_bytes(builder, bytes, bits);
    for bit in carry_bits {
        builder.assert_bool(*bit);
    }

    let mut total = incoming;
    for (sample, encoding) in encodings.iter().enumerate() {
        for half in 0..2 {
            if column >= half {
                let weight = Goldilocks::from_i32(coefficient(sample, column - half));
                for byte in 0..4 {
                    total += encoding[half * 4 + byte]
                        * (weight * Goldilocks::from_u64(1 << (byte * 8)));
                }
            }
        }
    }

    let mut output = AB::Expr::ZERO;
    for (index, byte) in bytes.iter().enumerate() {
        output += *byte * Goldilocks::from_u64(1 << (index * 8));
    }

    let outgoing = carry::<AB::Expr>(carry_bits);
    builder.assert_eq(
        total,
        output + outgoing.clone() * Goldilocks::from_i64(RADIX),
    );

    outgoing
}

/// Writes a word, its byte bits and its biased carry using only guarded integer temporaries.
///
/// The incoming carry must come from the preceding assignment or be zero initially.
#[cfg(any(test, feature = "prover"))]
pub(super) fn assign(
    values: &[Goldilocks; SAMPLES],
    column: usize,
    incoming: &mut i64,
    bytes: &mut [Goldilocks; 4],
    bits: &mut [[Goldilocks; 8]; 4],
    carry_bits: &mut [Goldilocks; CARRY_BITS],
) {
    assert!(column < WORDS);
    let mut total = Zeroizing::new(*incoming);
    for (sample, value) in values.iter().enumerate() {
        let word = Zeroizing::new(value.as_canonical_u64());
        for half in 0..2 {
            if column >= half {
                *total += i64::from(coefficient(sample, column - half))
                    * ((*word >> (half * 32)) as u32 as i64);
            }
        }
    }

    let output = Zeroizing::new(total.rem_euclid(RADIX) as u32);
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = Goldilocks::from_u32((*output >> (index * 8)) & 255);
    }

    assign_bytes(bytes, bits).expect("integer output bytes are in range");
    *incoming = total.div_euclid(RADIX);
    let encoded = Zeroizing::new((*incoming + BIAS) as u32);
    for (index, bit) in carry_bits.iter_mut().enumerate() {
        *bit = Goldilocks::from_u32((*encoded >> index) & 1);
    }
}
