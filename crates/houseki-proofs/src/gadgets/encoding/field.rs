//! Canonical little endian byte decomposition of Goldilocks field values.

#[cfg(any(test, feature = "prover"))]
use super::assign_bytes;
use super::eval_bytes;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
#[cfg(any(test, feature = "prover"))]
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Constrains a field value to its unique eight byte little endian representation.
///
/// The byte ranges contribute 72 equations and six further equations enforce reconstruction
/// and canonicality, with maximum degree two.
///
/// For the Goldilocks modulus `2^64 - 2^32 + 1`, a range checked encoding is canonical exactly
/// when its high word is below `u32::MAX` or its low word is zero.
///
/// `high_is_max` indicates a zero gap between the high word and `u32::MAX`, while
/// `high_gap_inverse` is the inverse of a nonzero gap and zero otherwise.
///
/// Constraining the low word to zero when the gap vanishes excludes modulus aliases that
/// field reconstruction alone would accept.
///
/// The caller supplies all cells and remains responsible for trace scheduling and circuit links.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "circuit consumers follow in later increments")
)]
pub(crate) fn eval_field_bytes<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    value: AB::Var,
    bytes: &[AB::Var; 8],
    bits: &[[AB::Var; 8]; 8],
    high_is_max: AB::Var,
    high_gap_inverse: AB::Var,
) {
    eval_bytes(builder, bytes, bits);

    let mut low = AB::Expr::ZERO;
    let mut high = AB::Expr::ZERO;
    for index in 0..4 {
        let weight = Goldilocks::from_u64(1 << (8 * index));
        low += bytes[index] * weight;
        high += bytes[index + 4] * weight;
    }

    let gap = AB::Expr::from(Goldilocks::from_u32(u32::MAX)) - high.clone();
    builder.assert_bool(high_is_max);
    builder.assert_zero(gap.clone() * high_is_max);
    builder.assert_eq(gap * high_gap_inverse, AB::Expr::ONE - high_is_max);
    builder.assert_zero(high_is_max * high_gap_inverse);
    builder.assert_zero(high_is_max * low.clone());
    builder.assert_eq(value, low + high * Goldilocks::from_u64(1 << 32));
}

/// Writes canonical bytes, bits and helper cells into caller-owned storage.
///
/// Native field values always have a canonical encoding, so assignment is infallible and
/// overwrites every destination cell without allocating.
///
/// The inverse uses the fixed public exponent `p - 2`, which maps a zero gap to zero and avoids
/// the backend inverse's input-dependent iteration count.
///
/// The caller retains cleanup responsibility for the input and destination, while canonical
/// integer temporaries are wiped on return.
///
/// Assignment does not establish constraints, so the consuming AIR must call [`eval_field_bytes`].
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "circuit trace builders follow in later increments"
    )
)]
pub(crate) fn assign_field_bytes(
    value: &Goldilocks,
    bytes: &mut [Goldilocks; 8],
    bits: &mut [[Goldilocks; 8]; 8],
    high_is_max: &mut Goldilocks,
    high_gap_inverse: &mut Goldilocks,
) {
    let word = Zeroizing::new(value.as_canonical_u64());
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = Goldilocks::from_u64((*word >> (8 * index)) & 255);
    }

    assign_bytes(bytes, bits).expect("canonical byte decomposition is in range");

    let gap = Zeroizing::new(u64::from(u32::MAX) - (*word >> 32));
    *high_is_max = Goldilocks::from_bool(*gap == 0);
    *high_gap_inverse = Goldilocks::from_u64(*gap).exp_const_u64::<{ Goldilocks::ORDER_U64 - 2 }>();
}

/// Native boundaries and forged encodings that bypass the honest assignment helper.
#[cfg(test)]
mod tests {
    use crate::gadgets::FieldAir;
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    /// Starts with occupied cells so missed assignment writes cannot appear as valid zeros.
    fn assigned(value: u64) -> [Goldilocks; 75] {
        let mut row = [Goldilocks::NEG_ONE; 75];
        FieldAir::assign_row(&Goldilocks::from_u64(value), &mut row);

        row
    }

    /// Checks supplied cells independently of their construction.
    fn evaluate(row: &[Goldilocks; 75], expected: Goldilocks) -> ConstraintReport {
        let matrix = RowMajorMatrix::new(row.repeat(2), 75);
        check_all_constraints(&FieldAir, &matrix, &[expected], Some(64))
    }

    /// Independent literal vectors establish orientation and both modulus boundary cases.
    #[test]
    fn canonical_assignment_matches_native_boundary_vectors() {
        let cases = [
            (0, [0; 8]),
            (255, [255, 0, 0, 0, 0, 0, 0, 0]),
            (256, [0, 1, 0, 0, 0, 0, 0, 0]),
            (0xffff_ffff, [255, 255, 255, 255, 0, 0, 0, 0]),
            (0x1_0000_0000, [0, 0, 0, 0, 1, 0, 0, 0]),
            (0x0123_4567_89ab_cdef, [239, 205, 171, 137, 103, 69, 35, 1]),
            (
                Goldilocks::ORDER_U64 - 2,
                [255, 255, 255, 255, 254, 255, 255, 255],
            ),
            (Goldilocks::ORDER_U64 - 1, [0, 0, 0, 0, 255, 255, 255, 255]),
        ];
        for (word, expected) in cases {
            let row = assigned(word);

            assert_eq!(row[1..9], expected.map(Goldilocks::from_u8));
            for (byte, bits) in expected.iter().zip(row[9..73].as_chunks::<8>().0) {
                for (index, bit) in bits.iter().enumerate() {
                    assert_eq!(*bit, Goldilocks::from_bool(byte & (1 << index) != 0));
                }
            }

            let gap = Goldilocks::from_u64(u64::from(u32::MAX) - (word >> 32));
            assert_eq!(
                row[73],
                Goldilocks::from_bool(word == Goldilocks::ORDER_U64 - 1)
            );
            if gap == Goldilocks::ZERO {
                assert_eq!(row[74], Goldilocks::ZERO);
            } else {
                assert_eq!(gap * row[74], Goldilocks::ONE);
            }

            assert!(evaluate(&row, row[0]).is_ok());
        }
    }

    /// Canonicalization also handles the backend's redundant internal field representations.
    #[test]
    fn assignment_canonicalizes_redundant_native_values() {
        for word in [Goldilocks::ORDER_U64, Goldilocks::ORDER_U64 + 1, u64::MAX] {
            let row = assigned(word);
            let canonical = word % Goldilocks::ORDER_U64;

            assert_eq!(row[1..9], canonical.to_le_bytes().map(Goldilocks::from_u8));
            assert!(evaluate(&row, row[0]).is_ok());
        }
    }

    /// Every byte, bit and helper affects the relation for both canonicality branches.
    #[test]
    fn every_encoding_cell_is_constrained() {
        for word in [0x0123_4567_89ab_cdef, Goldilocks::ORDER_U64 - 1] {
            let original = assigned(word);
            for index in 1..75 {
                let mut row = original;
                row[index] += Goldilocks::ONE;

                assert!(!evaluate(&row, row[0]).is_ok(), "cell {index}");
            }
        }
    }

    /// Reconstruction binds the encoding even when the public scalar follows the forgery.
    #[test]
    fn changed_scalar_cannot_reuse_valid_encoding() {
        let mut row = assigned(255);
        row[0] += Goldilocks::ONE;

        assert!(!evaluate(&row, row[0]).is_ok());
    }

    /// A zero low word cannot excuse marking an ordinary high word as maximal.
    #[test]
    fn nonzero_gap_cannot_claim_maximal_high_word() {
        let mut row = assigned(0);
        row[73] = Goldilocks::ONE;
        row[74] = Goldilocks::ZERO;

        assert!(!evaluate(&row, row[0]).is_ok());
    }

    /// Field equality alone would accept these u64 encodings of smaller scalar values.
    #[test]
    fn modulus_aliases_are_rejected_with_valid_byte_ranges() {
        for word in [Goldilocks::ORDER_U64, Goldilocks::ORDER_U64 + 1, u64::MAX] {
            let mut row = assigned(Goldilocks::ORDER_U64 - 1);
            row[0] = Goldilocks::from_u64(word);
            for (index, byte) in word.to_le_bytes().iter().enumerate() {
                row[1 + index] = Goldilocks::from_u8(*byte);
                for bit in 0..8 {
                    row[9 + index * 8 + bit] = Goldilocks::from_bool(byte & (1 << bit) != 0);
                }
            }

            assert!(!evaluate(&row, row[0]).is_ok());
        }
    }

    /// Forged canonicality helpers cannot disguise the first modulus alias as zero.
    #[test]
    fn modulus_alias_cannot_clear_the_high_word_indicator() {
        let mut row = assigned(Goldilocks::ORDER_U64 - 1);
        row[0] = Goldilocks::ZERO;
        row[1] = Goldilocks::ONE;
        row[9] = Goldilocks::ONE;
        row[73] = Goldilocks::ZERO;
        row[74] = Goldilocks::ONE;

        assert!(!evaluate(&row, row[0]).is_ok());
    }

    /// Matching both reconstruction equations cannot replace Boolean bits with field values.
    #[test]
    fn matching_non_boolean_encoding_is_rejected() {
        let mut row = assigned(0);
        row[0] = Goldilocks::TWO;
        row[1] = Goldilocks::TWO;
        row[9] = Goldilocks::TWO;

        assert!(!evaluate(&row, row[0]).is_ok());
    }
}
