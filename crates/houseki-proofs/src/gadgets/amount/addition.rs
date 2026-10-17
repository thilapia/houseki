//! Exact addition with byte ranges and a bounded carry at every limb boundary.

#[cfg(any(test, feature = "prover"))]
use super::{AmountError, integer};
#[cfg(any(test, feature = "prover"))]
use crate::gadgets::assign_bytes;
use crate::gadgets::eval_bytes;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Constrains the complete integer sum of two sixteen byte operands without overflow.
///
/// Every operand and result limb receives its own byte range check, while Boolean carries
/// connect adjacent limbs with initial and final carries fixed to zero.
///
/// Both sides of each byte equation are at most 511, so field equality establishes integer
/// equality and the final zero carry prevents wraparound at 128 bits.
///
/// This relation permits totals larger than one ordinary amount and does not enforce the
/// individual amount cap, positivity or payment conservation by itself.
///
/// The caller retains responsibility for scheduling and linking these cells to its circuit.
pub(crate) fn eval_addition<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    operands: [&[AB::Var; 16]; 2],
    operand_bits: [&[[AB::Var; 8]; 16]; 2],
    sum: &[AB::Var; 16],
    sum_bits: &[[AB::Var; 8]; 16],
    carries: &[AB::Var; 16],
) {
    for (operand, bits) in operands.iter().zip(operand_bits) {
        eval_bytes(builder, operand, bits);
    }

    eval_bytes(builder, sum, sum_bits);
    eval_carries(builder, operands, sum.map(Into::into), carries);
}

/// Validates operands and assigns the exact sum, bit decompositions and carries.
///
/// All input validation precedes destination writes, and successful assignment overwrites every
/// destination cell without allocation or a new witness owner.
///
/// Decoded operands, the sum and carry temporaries are guarded, while the caller retains cleanup
/// responsibility for its borrowed source and destination field cells.
///
/// Assignment does not establish constraints, so the consuming AIR must call [`eval_addition`].
///
/// # Errors
///
/// Reports [`AmountError::InvalidLimb`] for the left operand before the right, then
/// [`AmountError::Overflow`] if their exact sum exceeds `u128::MAX`.
///
/// Every failure leaves all destinations unchanged.
#[cfg(any(test, feature = "prover"))]
pub(crate) fn assign_addition(
    operands: [&[Goldilocks; 16]; 2],
    operand_bits: [&mut [[Goldilocks; 8]; 16]; 2],
    sum: &mut [Goldilocks; 16],
    sum_bits: &mut [[Goldilocks; 8]; 16],
    carries: &mut [Goldilocks; 16],
) -> Result<(), AmountError> {
    let left = integer::read(operands[0])?;
    let right = integer::read(operands[1])?;
    let total = Zeroizing::new(left.checked_add(*right).ok_or(AmountError::Overflow)?);
    for (operand, bits) in operands.iter().zip(operand_bits) {
        assign_bytes(operand, bits).expect("validated operand bytes are in range");
    }

    integer::write(&total, sum);
    assign_bytes(sum, sum_bits).expect("integer output bytes are in range");
    assign_carries([&left, &right], carries);

    Ok(())
}

/// Constrains carry propagation for byte operands and a byte result supplied by the caller.
///
/// Callers must range every operand and result limb independently or supply byte constants.
///
/// Each output carry is Boolean, the initial carry is zero and the last carry must be zero.
pub(super) fn eval_carries<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    operands: [&[AB::Var; 16]; 2],
    sum: [AB::Expr; 16],
    carries: &[AB::Var; 16],
) {
    let mut incoming = AB::Expr::ZERO;
    for (index, outgoing) in carries.iter().enumerate() {
        builder.assert_bool(*outgoing);
        builder.assert_eq(
            operands[0][index] + operands[1][index] + incoming,
            sum[index].clone() + *outgoing * Goldilocks::from_u16(256),
        );
        incoming = (*outgoing).into();
    }

    builder.assert_zero(incoming);
}

/// Assigns all output carries from borrowed integers without a second operand representation.
///
/// The caller checks capacity before assignment when a final overflow carry is forbidden.
#[cfg(any(test, feature = "prover"))]
pub(super) fn assign_carries(operands: [&u128; 2], carries: &mut [Goldilocks; 16]) {
    let mut carry = Zeroizing::new(0_u16);
    for (index, destination) in carries.iter_mut().enumerate() {
        *carry += ((operands[0] >> (8 * index)) & 255) as u16;
        *carry += ((operands[1] >> (8 * index)) & 255) as u16;
        *carry >>= 8;
        *destination = Goldilocks::from_u16(*carry);
    }
}

/// Native integer conformance and adversarial rows independent of honest assignment.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::AdditionAir;
    use houseki_types::Amount;
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
    use p3_matrix::dense::RowMajorMatrix;

    /// Builds a fixture from ordinary native integers with all destinations initially occupied.
    fn assigned(left: u128, right: u128) -> [Goldilocks; AdditionAir::WIDTH] {
        let operands = [left, right].map(|word| word.to_le_bytes().map(Goldilocks::from_u8));
        let mut row = [Goldilocks::NEG_ONE; AdditionAir::WIDTH];
        AdditionAir::assign_row([&operands[0], &operands[1]], &mut row).unwrap();

        row
    }

    /// Checks arithmetic even when the supplied public values follow a forged row.
    fn evaluate(row: &[Goldilocks; AdditionAir::WIDTH]) -> ConstraintReport {
        check_all_constraints(
            &AdditionAir,
            &RowMajorMatrix::new(row.repeat(2), AdditionAir::WIDTH),
            &row[..48],
            Some(64),
        )
    }

    /// Independently writes native bytes and bits without computing arithmetic witnesses.
    fn write_word(row: &mut [Goldilocks; AdditionAir::WIDTH], slot: usize, word: u128) {
        for (index, byte) in word.to_le_bytes().iter().enumerate() {
            row[slot * 16 + index] = Goldilocks::from_u8(*byte);
            for bit in 0..8 {
                row[48 + slot * 128 + index * 8 + bit] =
                    Goldilocks::from_bool(byte & (1 << bit) != 0);
            }
        }
    }

    /// Preserves byte carries, high words, the field modulus and totals above one amount.
    #[test]
    fn addition_matches_exact_native_integer_vectors() {
        for (left, right, expected) in [
            (0, 0, 0),
            (1, 2, 3),
            (255, 1, 256),
            (65535, 1, 65536),
            ((1_u128 << 64) - 1, 1, 1_u128 << 64),
            (
                u128::from(Goldilocks::ORDER_U64) - 1,
                1,
                u128::from(Goldilocks::ORDER_U64),
            ),
            (Amount::MAX_ATOMS, Amount::MAX_ATOMS, 2 * Amount::MAX_ATOMS),
            (
                2 * Amount::MAX_ATOMS,
                Amount::MAX_ATOMS,
                3 * Amount::MAX_ATOMS,
            ),
            (u128::MAX - 1, 1, u128::MAX),
        ] {
            let row = assigned(left, right);

            assert_eq!(row[32..48], expected.to_le_bytes().map(Goldilocks::from_u8));
            assert!(evaluate(&row).is_ok());
        }
    }

    /// A prior sum remains reusable above one amount's cap, and the final addend cannot be omitted.
    #[test]
    fn chained_additions_preserve_the_full_total_and_fee_contribution() {
        let first = assigned(Amount::MAX_ATOMS, Amount::MAX_ATOMS);
        let fee = Amount::MAX_ATOMS.to_le_bytes().map(Goldilocks::from_u8);
        let mut second = [Goldilocks::NEG_ONE; AdditionAir::WIDTH];
        AdditionAir::assign_row([first[32..48].try_into().unwrap(), &fee], &mut second).unwrap();

        assert!(evaluate(&first).is_ok());
        assert!(evaluate(&second).is_ok());
        assert_eq!(
            second[32..48],
            (3 * Amount::MAX_ATOMS)
                .to_le_bytes()
                .map(Goldilocks::from_u8)
        );

        write_word(&mut second, 2, 2 * Amount::MAX_ATOMS);

        assert!(!evaluate(&second).is_ok());
    }

    /// Each byte, bit and carry participates even when public fixture values are changed too.
    #[test]
    fn every_addition_cell_is_constrained() {
        let original = assigned(65535, 1);
        for index in 0..AdditionAir::WIDTH {
            let mut row = original;
            row[index] += Goldilocks::ONE;

            assert!(!evaluate(&row).is_ok(), "cell {index}");
        }
    }

    /// Every limb equation is required even when all byte range constraints remain satisfied.
    #[test]
    fn each_limb_equation_rejects_a_valid_byte_change() {
        let original = assigned(0, 0);
        for slot in 0..3 {
            for index in 0..16 {
                let mut row = original;
                write_word(&mut row, slot, 1_u128 << (8 * index));

                assert!(!evaluate(&row).is_ok(), "operand {slot}, limb {index}");
            }
        }
    }

    /// Shifted modulus multiples cannot disappear from low or high limbs through fractional carries.
    #[test]
    fn modular_alias_cannot_use_non_boolean_carries() {
        let inverse_radix = Goldilocks::from_u16(256).inverse();
        for shift in 0..=8 {
            let mut row = [Goldilocks::ZERO; AdditionAir::WIDTH];
            write_word(
                &mut row,
                0,
                u128::from(Goldilocks::ORDER_U64) << (8 * shift),
            );
            let mut carry = Goldilocks::ZERO;
            for index in 0..16 {
                carry = (row[index] + carry) * inverse_radix;
                row[432 + index] = carry;
            }

            assert_eq!(carry, Goldilocks::ZERO);
            assert!(!evaluate(&row).is_ok());
        }
    }

    /// Correct byte equations and Boolean carries still cannot permit a final overflow carry.
    #[test]
    fn overflow_cannot_wrap_at_the_final_limb() {
        let mut row = [Goldilocks::ZERO; AdditionAir::WIDTH];
        write_word(&mut row, 0, u128::MAX);
        write_word(&mut row, 1, 1);
        row[432..].fill(Goldilocks::ONE);

        assert!(!evaluate(&row).is_ok());
    }

    /// Operand validation and capacity rejection precede every destination write.
    #[test]
    fn invalid_operands_and_overflow_preserve_all_destinations() {
        let maximum = u128::MAX.to_le_bytes().map(Goldilocks::from_u8);
        let one = 1_u128.to_le_bytes().map(Goldilocks::from_u8);
        check_rejection([&maximum, &one], AmountError::Overflow);

        for operand in 0..2 {
            for index in 0..16 {
                let mut values = [[Goldilocks::ZERO; 16]; 2];
                values[operand][index] = Goldilocks::from_u16(256);

                check_rejection([&values[0], &values[1]], AmountError::InvalidLimb);
            }
        }
    }

    /// Checks the whole assignment destination after a redacted failure.
    fn check_rejection(operands: [&[Goldilocks; 16]; 2], expected: AmountError) {
        let mut left_bits = [[Goldilocks::NEG_ONE; 8]; 16];
        let mut right_bits = left_bits;
        let mut sum = [Goldilocks::NEG_ONE; 16];
        let mut sum_bits = left_bits;
        let mut carries = sum;
        let result = assign_addition(
            operands,
            [&mut left_bits, &mut right_bits],
            &mut sum,
            &mut sum_bits,
            &mut carries,
        );

        assert_eq!(result, Err(expected));
        assert_eq!(left_bits, [[Goldilocks::NEG_ONE; 8]; 16]);
        assert_eq!(right_bits, left_bits);
        assert_eq!(sum_bits, left_bits);
        assert_eq!(sum, [Goldilocks::NEG_ONE; 16]);
        assert_eq!(carries, sum);
    }
}
