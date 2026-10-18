//! Individual amount caps with a separate positive-note policy selected by the circuit.

#[cfg(test)]
mod air;

#[cfg(test)]
pub(crate) use air::AmountAir;

use super::addition::eval_carries;
#[cfg(any(test, feature = "prover"))]
use super::{AmountError, addition::assign_carries, integer};
#[cfg(any(test, feature = "prover"))]
use crate::gadgets::assign_bytes;
use crate::gadgets::eval_bytes;
use houseki_types::Amount;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
#[cfg(any(test, feature = "prover"))]
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Constrains sixteen byte limbs to the native amount cap and the selected positivity policy.
///
/// Ranged amount and remainder limbs must add exactly to [`Amount::MAX_ATOMS`] with Boolean
/// carries and no final overflow, establishing the bound independently of honest assignment.
///
/// With `POSITIVE` set, the byte sum times `nonzero_inverse` must equal one, excluding zero
/// because the byte sum lies in `0..=4080`, below the field modulus.
///
/// Without that policy, zero is allowed and the unused inverse is constrained to zero.
///
/// The policy is fixed by circuit code, and the caller owns scheduling and all circuit links.
pub(crate) fn eval_amount<const POSITIVE: bool, AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    amount: &[AB::Var; 16],
    amount_bits: &[[AB::Var; 8]; 16],
    remainder: &[AB::Var; 16],
    remainder_bits: &[[AB::Var; 8]; 16],
    carries: &[AB::Var; 16],
    nonzero_inverse: AB::Var,
) {
    eval_bytes(builder, amount, amount_bits);
    eval_bytes(builder, remainder, remainder_bits);
    let maximum = Amount::MAX_ATOMS
        .to_le_bytes()
        .map(|byte| AB::Expr::from(Goldilocks::from_u8(byte)));
    eval_carries(builder, [amount, remainder], maximum, carries);

    if POSITIVE {
        let sum = amount.iter().fold(AB::Expr::ZERO, |sum, limb| sum + *limb);
        builder.assert_one(sum * nonzero_inverse);
    } else {
        builder.assert_zero(nonzero_inverse);
    }
}

/// Validates a borrowed amount and fills caller-owned bound and positivity auxiliaries.
///
/// Every destination is overwritten on success without allocating or retaining another amount
/// owner, while decoded values, the remainder, byte sum and carry temporaries are guarded.
///
/// Positivity uses a fixed public exponent for inverse assignment, and a zero-permitting
/// assignment writes zero to the unused inverse cell.
///
/// The caller retains cleanup responsibility for its field cells and must use [`eval_amount`]
/// to enforce the relation independently of assignment.
///
/// # Errors
///
/// Reports [`AmountError::InvalidLimb`] before checking the amount cap and positivity policy,
/// which return [`AmountError::OutOfRange`] when violated.
///
/// Every failure leaves all destinations unchanged.
#[cfg(any(test, feature = "prover"))]
pub(crate) fn assign_amount<const POSITIVE: bool>(
    amount: &[Goldilocks; 16],
    amount_bits: &mut [[Goldilocks; 8]; 16],
    remainder: &mut [Goldilocks; 16],
    remainder_bits: &mut [[Goldilocks; 8]; 16],
    carries: &mut [Goldilocks; 16],
    nonzero_inverse: &mut Goldilocks,
) -> Result<(), AmountError> {
    let value = integer::read(amount)?;
    if *value > Amount::MAX_ATOMS || (POSITIVE && *value == 0) {
        return Err(AmountError::OutOfRange);
    }

    let difference = Zeroizing::new(Amount::MAX_ATOMS - *value);
    assign_bytes(amount, amount_bits).expect("validated amount bytes are in range");
    integer::write(&difference, remainder);
    assign_bytes(remainder, remainder_bits).expect("integer remainder bytes are in range");
    assign_carries([&value, &difference], carries);

    if POSITIVE {
        let mut sum = Zeroizing::new(0_u16);
        for index in 0..16 {
            *sum += ((*value >> (8 * index)) & 255) as u16;
        }

        *nonzero_inverse =
            Goldilocks::from_u16(*sum).exp_const_u64::<{ Goldilocks::ORDER_U64 - 2 }>();
    } else {
        *nonzero_inverse = Goldilocks::ZERO;
    }

    Ok(())
}

/// Native amount conformance and direct forgeries of the independent constraint relation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::AmountAir;
    use houseki_types::Amount;
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
    use p3_matrix::dense::RowMajorMatrix;

    /// Assigns only public test values with every destination initially occupied.
    fn assigned<const POSITIVE: bool>(value: u128) -> [Goldilocks; 305] {
        let mut row = [Goldilocks::NEG_ONE; 305];
        AmountAir::<POSITIVE>::assign_row(&value.to_le_bytes().map(Goldilocks::from_u8), &mut row)
            .unwrap();

        row
    }

    /// Lets expected public bytes follow the forged row so they cannot mask missing constraints.
    fn evaluate<const POSITIVE: bool>(row: &[Goldilocks; 305]) -> ConstraintReport {
        check_all_constraints(
            &AmountAir::<POSITIVE>,
            &RowMajorMatrix::new(row.repeat(2), 305),
            &row[..16],
            Some(64),
        )
    }

    /// Writes independent amount or remainder bytes and bits without honest bound assignment.
    fn write_word(row: &mut [Goldilocks; 305], slot: usize, word: u128) {
        for (index, byte) in word.to_le_bytes().iter().enumerate() {
            row[16 * slot + index] = Goldilocks::from_u8(*byte);
            for bit in 0..8 {
                row[32 + 128 * slot + 8 * index + bit] =
                    Goldilocks::from_bool(byte & (1 << bit) != 0);
            }
        }
    }

    /// Native legal amounts remain exact across byte, word and cap boundaries.
    #[test]
    fn amount_assignment_matches_native_boundaries() {
        for value in [
            1,
            255,
            256,
            (1_u128 << 64) - 1,
            1_u128 << 64,
            Amount::MAX_ATOMS - 1,
            Amount::MAX_ATOMS,
        ] {
            let native = Amount::from_atoms(value).unwrap();
            let note = assigned::<true>(value);
            let fee = assigned::<false>(value);

            assert_eq!(note[..16], native.to_le_bytes().map(Goldilocks::from_u8));
            assert_eq!(
                note[16..32],
                (Amount::MAX_ATOMS - value)
                    .to_le_bytes()
                    .map(Goldilocks::from_u8)
            );
            assert!(evaluate::<true>(&note).is_ok());
            assert!(evaluate::<false>(&fee).is_ok());
            assert_eq!(fee[304], Goldilocks::ZERO);
        }

        assert!(evaluate::<false>(&assigned::<false>(0)).is_ok());
    }

    /// Zero fees are valid while the positive note relation rejects zero for every inverse.
    #[test]
    fn zero_note_cannot_fake_positivity() {
        for inverse in [Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::NEG_ONE] {
            let mut row = assigned::<false>(0);
            row[304] = inverse;

            assert!(!evaluate::<true>(&row).is_ok());
        }
    }

    /// Every bound auxiliary is constrained under both policies, including the unused fee inverse.
    #[test]
    fn every_amount_cell_is_constrained() {
        let positive = assigned::<true>(255);
        let fee = assigned::<false>(255);
        for index in 0..305 {
            let mut note_row = positive;
            note_row[index] += Goldilocks::ONE;
            let mut fee_row = fee;
            fee_row[index] += Goldilocks::ONE;

            assert!(!evaluate::<true>(&note_row).is_ok(), "note cell {index}");
            assert!(!evaluate::<false>(&fee_row).is_ok(), "fee cell {index}");
        }
    }

    /// Each comparison limb remains linked to the cap when a byte and its bits change together.
    #[test]
    fn each_bound_limb_rejects_a_valid_byte_change() {
        let original = assigned::<false>(Amount::MAX_ATOMS);
        for index in 0..16 {
            let mut row = original;
            write_word(&mut row, 0, Amount::MAX_ATOMS ^ (1_u128 << (8 * index)));

            assert!(!evaluate::<false>(&row).is_ok(), "limb {index}");
        }
    }

    /// An amount above the cap cannot use a wrapping negative remainder and final carry.
    #[test]
    fn above_cap_cannot_wrap_the_comparison() {
        let mut row = assigned::<false>(0);
        write_word(&mut row, 0, Amount::MAX_ATOMS + 1);
        write_word(&mut row, 1, u128::MAX);
        let mut carry = 0_u16;
        for index in 0..16 {
            carry = (row[index].as_canonical_u64() as u16
                + row[16 + index].as_canonical_u64() as u16
                + carry)
                >> 8;
            row[288 + index] = Goldilocks::from_u16(carry);
        }

        assert_eq!(carry, 1);
        assert!(!evaluate::<false>(&row).is_ok());
    }

    /// Congruent field totals cannot hide excessive high limbs through fractional carries.
    #[test]
    fn above_cap_cannot_use_a_field_modulus_alias() {
        let modulus = u128::from(Goldilocks::ORDER_U64);
        let inverse_radix = Goldilocks::from_u16(256).inverse();
        for value in [
            Amount::MAX_ATOMS + 1,
            1_u128 << 104,
            1_u128 << 112,
            1_u128 << 120,
            u128::MAX,
        ] {
            let remainder = (Amount::MAX_ATOMS % modulus + modulus - value % modulus) % modulus;
            let mut row = assigned::<false>(0);
            write_word(&mut row, 0, value);
            write_word(&mut row, 1, remainder);
            let mut carry = Goldilocks::ZERO;
            for (index, maximum) in Amount::MAX_ATOMS.to_le_bytes().iter().enumerate() {
                carry = (row[index] + row[16 + index] + carry - Goldilocks::from_u8(*maximum))
                    * inverse_radix;
                row[288 + index] = carry;
            }

            assert_eq!(carry, Goldilocks::ZERO);
            assert!(!evaluate::<false>(&row).is_ok());
        }
    }

    /// Range and positivity errors leave every caller-owned destination unchanged.
    #[test]
    fn amount_rejections_are_atomic_and_match_native_policy() {
        check_rejection::<true>(&[Goldilocks::ZERO; 16], AmountError::OutOfRange);
        for value in [Amount::MAX_ATOMS + 1, 1_u128 << 127, u128::MAX] {
            assert!(Amount::from_atoms(value).is_err());
            let amount = value.to_le_bytes().map(Goldilocks::from_u8);
            check_rejection::<true>(&amount, AmountError::OutOfRange);
            check_rejection::<false>(&amount, AmountError::OutOfRange);
        }

        for index in 0..16 {
            let mut amount = [Goldilocks::ZERO; 16];
            amount[index] = Goldilocks::from_u16(256);

            check_rejection::<true>(&amount, AmountError::InvalidLimb);
        }
    }

    /// Verifies every mutable output after a rejected assignment.
    fn check_rejection<const POSITIVE: bool>(amount: &[Goldilocks; 16], expected: AmountError) {
        let mut amount_bits = [[Goldilocks::NEG_ONE; 8]; 16];
        let mut remainder = [Goldilocks::NEG_ONE; 16];
        let mut remainder_bits = amount_bits;
        let mut carries = remainder;
        let mut inverse = Goldilocks::NEG_ONE;
        let result = assign_amount::<POSITIVE>(
            amount,
            &mut amount_bits,
            &mut remainder,
            &mut remainder_bits,
            &mut carries,
            &mut inverse,
        );

        assert_eq!(result, Err(expected));
        assert_eq!(amount_bits, [[Goldilocks::NEG_ONE; 8]; 16]);
        assert_eq!(remainder_bits, amount_bits);
        assert_eq!(remainder, [Goldilocks::NEG_ONE; 16]);
        assert_eq!(carries, remainder);
        assert_eq!(inverse, Goldilocks::NEG_ONE);
    }
}
