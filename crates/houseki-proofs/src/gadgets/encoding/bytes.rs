//! Fixed-width byte ranges without truncation or integer reduction.

use super::eval_byte;
#[cfg(any(test, feature = "prover"))]
use super::{EncodingError, assign_byte};
use p3_air::AirBuilder;
#[cfg(any(test, feature = "prover"))]
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Constrains every value and its eight bits in arrays with the same fixed length.
///
/// Each position contributes the nine equations from [`eval_byte`], with no integer reduction
/// or omitted high bytes even for identifiers wider than a field element.
///
/// The caller retains responsibility for trace scheduling and linking every byte to its circuit.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "circuit consumers follow in later increments")
)]
pub(crate) fn eval_bytes<const N: usize, AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    values: &[AB::Var; N],
    bits: &[[AB::Var; 8]; N],
) {
    for (value, decomposition) in values.iter().zip(bits) {
        eval_byte(builder, *value, decomposition);
    }
}

/// Assigns every decomposition after validating the complete input array.
///
/// No allocation occurs and every destination cell is overwritten on success, with the caller
/// retaining cleanup responsibility for both arrays.
///
/// Canonical integer temporaries are wiped on return, including early rejection.
///
/// Assignment does not establish constraints, so the consuming AIR must call [`eval_bytes`].
///
/// # Errors
///
/// Returns [`EncodingError::InvalidByte`] without changing any destination cell if any input's
/// canonical value exceeds 255.
#[cfg(any(test, feature = "prover"))]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "circuit trace builders follow in later increments"
    )
)]
pub(crate) fn assign_bytes<const N: usize>(
    values: &[Goldilocks; N],
    bits: &mut [[Goldilocks; 8]; N],
) -> Result<(), EncodingError> {
    for value in values {
        let word = Zeroizing::new(value.as_canonical_u64());
        if *word > u64::from(u8::MAX) {
            return Err(EncodingError::InvalidByte);
        }
    }

    for (value, decomposition) in values.iter().zip(bits) {
        assign_byte(value, decomposition)?;
    }

    Ok(())
}

/// Fixed lengths, complete identifier coverage and atomic assignment failures.
#[cfg(test)]
mod tests {
    use crate::gadgets::{BytesAir, EncodingError, assign_bytes};
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    /// Evaluates supplied public fixtures without rebuilding their assignment.
    fn evaluate<const N: usize>(
        values: &[Goldilocks; N],
        bits: &[[Goldilocks; 8]; N],
        expected: &[Goldilocks],
    ) -> ConstraintReport {
        let mut row = values.to_vec();
        row.extend_from_slice(bits.as_flattened());

        let matrix = RowMajorMatrix::new(row.repeat(2), 9 * N);
        check_all_constraints(&BytesAir::<N>, &matrix, expected, Some(64))
    }

    /// Checks native bit values across a complete fixed-size representation.
    fn check_width<const N: usize>() {
        let native: [u8; N] = std::array::from_fn(|index| (index as u8).wrapping_mul(37));
        let values = native.map(Goldilocks::from_u8);
        let mut bits = [[Goldilocks::NEG_ONE; 8]; N];
        assign_bytes(&values, &mut bits).unwrap();

        for (byte, assigned) in native.iter().zip(&bits) {
            for (index, bit) in assigned.iter().enumerate() {
                assert_eq!(*bit, Goldilocks::from_bool(byte & (1 << index) != 0));
            }
        }

        assert!(evaluate(&values, &bits, &values).is_ok());
    }

    /// Retains lengths used by versions, field samples, amounts and full identifiers.
    #[test]
    fn fixed_width_assignments_match_native_bytes() {
        check_width::<1>();
        check_width::<4>();
        check_width::<8>();
        check_width::<16>();
        check_width::<64>();

        assert_eq!(assign_bytes(&[], &mut []), Ok(()));
    }

    /// Every invalid position is rejected before any preceding destination is written.
    #[test]
    fn invalid_byte_anywhere_preserves_all_destination_cells() {
        for index in 0..64 {
            let mut values = [Goldilocks::ZERO; 64];
            values[index] = Goldilocks::from_u16(256);
            let mut bits = [[Goldilocks::NEG_ONE; 8]; 64];
            let result = assign_bytes(&values, &mut bits);

            assert_eq!(result, Err(EncodingError::InvalidByte));
            assert_eq!(bits, [[Goldilocks::NEG_ONE; 8]; 64]);
        }
    }

    /// No byte or bit at the end of a long identifier can escape range enforcement.
    #[test]
    fn every_identifier_bit_is_constrained() {
        let values = [Goldilocks::ZERO; 64];
        for byte in 0..64 {
            for bit in 0..8 {
                let mut bits = [[Goldilocks::ZERO; 8]; 64];
                bits[byte][bit] = Goldilocks::ONE;

                assert!(!evaluate(&values, &bits, &values).is_ok());
            }
        }
    }

    /// A high byte cannot use a non-Boolean bit even with a matching reconstruction.
    #[test]
    fn final_byte_cannot_replace_bits_with_field_values() {
        let mut values = [Goldilocks::ZERO; 64];
        values[63] = Goldilocks::TWO;
        let mut bits = [[Goldilocks::ZERO; 8]; 64];
        bits[63][0] = Goldilocks::TWO;

        assert!(!evaluate(&values, &bits, &values).is_ok());
    }

    /// Complete public identifier linkage preserves every byte independently.
    #[test]
    fn each_public_identifier_byte_is_linked() {
        let values = [Goldilocks::ZERO; 64];
        let bits = [[Goldilocks::ZERO; 8]; 64];
        for index in 0..64 {
            let mut expected = values;
            expected[index] = Goldilocks::ONE;

            assert!(!evaluate(&values, &bits, &expected).is_ok());
        }
    }
}
