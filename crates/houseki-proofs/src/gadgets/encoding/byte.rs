//! Bit decomposition for byte values in the application field.

#[cfg(any(test, feature = "prover"))]
use super::EncodingError;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
#[cfg(any(test, feature = "prover"))]
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Constrains eight least significant first bits and their reconstruction of `value`.
///
/// Eight Boolean equations and one linear equality restrict the field value to `0..=255`.
///
/// The integer sum is below the Goldilocks modulus, so field equality cannot admit wraparound.
///
/// The caller supplies trace cells and retains responsibility for scheduling this relation and
/// linking the value to the rest of its circuit.
pub(crate) fn eval_byte<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    value: AB::Var,
    bits: &[AB::Var; 8],
) {
    let mut reconstructed = AB::Expr::ZERO;
    for (index, bit) in bits.iter().enumerate() {
        builder.assert_bool(*bit);
        reconstructed += *bit * Goldilocks::from_u16(1 << index);
    }

    builder.assert_eq(value, reconstructed);
}

/// Assigns a byte's bits into caller-owned storage without allocating.
///
/// The destination uses least significant bit order and every cell is overwritten on success.
///
/// The caller retains cleanup responsibility for the input and destination, and the temporary
/// canonical word is wiped on return.
///
/// Assignment does not establish constraints, so the consuming AIR must call [`eval_byte`].
///
/// # Errors
///
/// Returns [`EncodingError::InvalidByte`] before changing any destination cell when the canonical
/// input value exceeds 255.
#[cfg(any(test, feature = "prover"))]
pub(crate) fn assign_byte(
    value: &Goldilocks,
    bits: &mut [Goldilocks; 8],
) -> Result<(), EncodingError> {
    let word = Zeroizing::new(value.as_canonical_u64());
    if *word > u64::from(u8::MAX) {
        return Err(EncodingError::InvalidByte);
    }

    for (index, bit) in bits.iter_mut().enumerate() {
        *bit = Goldilocks::from_u64((*word >> index) & 1);
    }

    Ok(())
}

/// Exhaustive native conformance and independent malicious assignments.
#[cfg(test)]
mod tests {
    use crate::gadgets::{ByteAir, EncodingError, assign_byte};
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    /// Evaluates supplied cells directly, bypassing the honest assignment helper.
    fn evaluate(value: Goldilocks, bits: [Goldilocks; 8]) -> ConstraintReport {
        let mut row = vec![value];
        row.extend(bits);

        let matrix = RowMajorMatrix::new(row.repeat(2), 9);
        check_all_constraints(&ByteAir, &matrix, &[value], Some(32))
    }

    /// Covers every byte and overwrites every previously occupied destination bit.
    #[test]
    fn all_bytes_match_native_bits_and_satisfy_constraints() {
        for byte in 0..=u8::MAX {
            let value = Goldilocks::from_u8(byte);
            let mut bits = [Goldilocks::NEG_ONE; 8];
            assign_byte(&value, &mut bits).unwrap();

            for (index, bit) in bits.iter().enumerate() {
                assert_eq!(*bit, Goldilocks::from_bool(byte & (1 << index) != 0));
            }

            assert!(evaluate(value, bits).is_ok(), "byte {byte}");
        }
    }

    /// Checks little endian orientation with an asymmetric hand-derived vector.
    #[test]
    fn assignment_uses_least_significant_bit_first() {
        let mut bits = [Goldilocks::ZERO; 8];
        assign_byte(&Goldilocks::from_u8(0x96), &mut bits).unwrap();

        assert_eq!(bits, [0, 1, 1, 0, 1, 0, 0, 1].map(Goldilocks::from_u8));
    }

    /// Rejects out-of-range input before touching the caller's destination.
    #[test]
    fn invalid_assignment_leaves_destination_unchanged() {
        for value in [Goldilocks::from_u16(256), Goldilocks::NEG_ONE] {
            let mut bits = [Goldilocks::ONE; 8];
            let result = assign_byte(&value, &mut bits);

            assert_eq!(result, Err(EncodingError::InvalidByte));
            assert_eq!(bits, [Goldilocks::ONE; 8]);
        }
    }

    /// A changed bit cannot satisfy the original byte's reconstruction equation.
    #[test]
    fn each_bit_is_linked_to_the_byte() {
        let value = Goldilocks::from_u8(0x96);
        let original = [0, 1, 1, 0, 1, 0, 0, 1].map(Goldilocks::from_u8);
        for index in 0..8 {
            let mut bits = original;
            bits[index] = Goldilocks::ONE - bits[index];

            assert!(!evaluate(value, bits).is_ok(), "bit {index}");
        }
    }

    /// Changing the value alone cannot reuse a valid decomposition.
    #[test]
    fn changed_byte_is_rejected_with_valid_bits() {
        assert!(!evaluate(Goldilocks::ONE, [Goldilocks::ZERO; 8]).is_ok());
        assert!(!evaluate(Goldilocks::from_u16(256), [Goldilocks::ZERO; 8]).is_ok());
        assert!(!evaluate(Goldilocks::NEG_ONE, [Goldilocks::ONE; 8]).is_ok());
    }

    /// Even a matching weighted sum cannot bypass an individual Boolean constraint.
    #[test]
    fn non_boolean_bits_are_rejected_even_when_reconstruction_matches() {
        for index in 0..8 {
            for forged in [Goldilocks::TWO, Goldilocks::NEG_ONE] {
                let mut bits = [Goldilocks::ZERO; 8];
                bits[index] = forged;
                let value = forged * Goldilocks::from_u16(1 << index);

                assert!(!evaluate(value, bits).is_ok(), "bit {index}");
            }
        }
    }
}
