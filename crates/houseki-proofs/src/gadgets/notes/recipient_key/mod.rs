//! Canonical polynomial coefficient encoding for ML-KEM-1024 recipient keys.

#[cfg(any(test, feature = "prover"))]
mod error;
#[cfg(test)]
mod pair_air;

#[cfg(any(test, feature = "prover"))]
pub(crate) use error::RecipientKeyError;
#[cfg(test)]
pub(crate) use pair_air::RecipientPairAir;

#[cfg(any(test, feature = "prover"))]
use crate::gadgets::assign_bytes;
use crate::gadgets::eval_bytes;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
#[cfg(any(test, feature = "prover"))]
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
#[cfg(any(test, feature = "prover"))]
use zeroize::Zeroizing;

/// Largest coefficient accepted by the native ML-KEM public key decoder.
const MAX_COEFFICIENT: u16 = 3328;

/// Constrains two canonical twelve bit coefficients packed into three little endian bytes.
///
/// The byte decompositions supply the low and high nibbles of the shared middle byte.
///
/// Each coefficient plus its twelve bit nonnegative difference must equal 3328, so their
/// sum is at most 8190 and field equality cannot admit integer wraparound.
///
/// The caller must apply this relation to all 512 pairs in the first 1536 key bytes, range
/// check the final 32 unrestricted seed bytes and link the complete encoding to its hash.
///
/// This operation owns no schedule or public values and establishes representation validity,
/// not honest key generation, recipient identity or possession of a private key.
pub(crate) fn eval_pair<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    bytes: &[AB::Var; 3],
    bits: &[[AB::Var; 8]; 3],
    differences: &[[AB::Var; 12]; 2],
) {
    eval_bytes(builder, bytes, bits);
    let mut low = AB::Expr::ZERO;
    let mut high = AB::Expr::ZERO;
    for index in 0..4 {
        low += bits[1][index] * Goldilocks::from_u16(1 << index);
        high += bits[1][index + 4] * Goldilocks::from_u16(1 << index);
    }

    let coefficients = [
        bytes[0] + low * Goldilocks::from_u16(256),
        high + bytes[2] * Goldilocks::from_u16(16),
    ];
    for (coefficient, difference) in coefficients.into_iter().zip(differences) {
        let mut reconstructed = AB::Expr::ZERO;
        for (index, bit) in difference.iter().enumerate() {
            builder.assert_bool(*bit);
            reconstructed += *bit * Goldilocks::from_u16(1 << index);
        }

        builder.assert_eq(
            coefficient + reconstructed,
            Goldilocks::from_u16(MAX_COEFFICIENT),
        );
    }
}

/// Assigns coefficient auxiliaries into caller-owned storage.
///
/// Every destination is overwritten on success without allocating, while canonical input
/// words, decoded coefficients and bound differences are wiped on return.
///
/// The caller retains cleanup responsibility for the input and destinations and must use
/// [`eval_pair`] to enforce the relation independently of assignment.
///
/// # Errors
///
/// Reports [`RecipientKeyError::InvalidByte`] if any source cell exceeds 255 before checking
/// coefficient bounds, which return [`RecipientKeyError::NonCanonicalCoefficient`].
///
/// Every failure leaves all destinations unchanged.
#[cfg(any(test, feature = "prover"))]
pub(crate) fn assign_pair(
    bytes: &[Goldilocks; 3],
    bits: &mut [[Goldilocks; 8]; 3],
    differences: &mut [[Goldilocks; 12]; 2],
) -> Result<(), RecipientKeyError> {
    let mut words = Zeroizing::new([0_u64; 3]);
    for (word, byte) in words.iter_mut().zip(bytes) {
        *word = byte.as_canonical_u64();
        if *word > u64::from(u8::MAX) {
            return Err(RecipientKeyError::InvalidByte);
        }
    }

    let coefficients = Zeroizing::new([
        words[0] | ((words[1] & 15) << 8),
        (words[1] >> 4) | (words[2] << 4),
    ]);
    if coefficients
        .iter()
        .any(|value| *value > u64::from(MAX_COEFFICIENT))
    {
        return Err(RecipientKeyError::NonCanonicalCoefficient);
    }

    assign_bytes(bytes, bits).expect("validated recipient bytes are in range");
    for (coefficient, destination) in coefficients.iter().zip(differences) {
        let difference = Zeroizing::new(u64::from(MAX_COEFFICIENT) - coefficient);
        for (index, bit) in destination.iter_mut().enumerate() {
            *bit = Goldilocks::from_u64((*difference >> index) & 1);
        }
    }

    Ok(())
}

/// Native coefficient boundaries and rejection independent of honest assignment.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::RecipientPairAir;
    #[cfg(feature = "prover")]
    use houseki_crypto::MlKem1024EncapsulationKey;
    #[cfg(feature = "prover")]
    use houseki_types::EncodedMlKem1024PublicKey;
    use p3_air::{ConstraintReport, check_all_constraints};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    /// Assigns public test bytes with all destinations initially occupied.
    fn assigned(bytes: [u8; 3]) -> [Goldilocks; 51] {
        let mut row = [Goldilocks::NEG_ONE; 51];
        RecipientPairAir::assign_row(&bytes.map(Goldilocks::from_u8), &mut row).unwrap();

        row
    }

    /// Evaluates supplied cells with matching public bytes, bypassing the native validator.
    fn evaluate(row: &[Goldilocks; 51]) -> ConstraintReport {
        check_all_constraints(
            &RecipientPairAir,
            &RowMajorMatrix::new(row.repeat(2), 51),
            &row[..3],
            Some(64),
        )
    }

    /// Packs public integer fixtures without using the gadget's assignment path.
    fn encoded_pair(first: u16, second: u16) -> [u8; 3] {
        [
            first as u8,
            ((first >> 8) | (second << 4)) as u8,
            (second >> 4) as u8,
        ]
    }

    /// Supplies independently packed bits with twelve bit wrapping bound differences.
    fn forged_pair(first: u16, second: u16) -> [Goldilocks; 51] {
        let mut row = [Goldilocks::ZERO; 51];
        for (index, byte) in encoded_pair(first, second).into_iter().enumerate() {
            row[index] = Goldilocks::from_u8(byte);
            for bit in 0..8 {
                row[3 + index * 8 + bit] = Goldilocks::from_bool(byte & (1 << bit) != 0);
            }
        }

        for (index, coefficient) in [first, second].into_iter().enumerate() {
            let difference = 3328_u16.wrapping_sub(coefficient) & 4095;
            for bit in 0..12 {
                row[27 + index * 12 + bit] = Goldilocks::from_bool(difference & (1 << bit) != 0);
            }
        }

        row
    }

    /// Literal boundary encodings exercise both halves of the shared middle byte.
    #[test]
    fn canonical_pair_boundaries_match_literal_differences() {
        for (bytes, expected) in [
            ([0x00, 0x00, 0x00], [3328_u16, 3328]),
            ([0x00, 0x0d, 0xd0], [0, 0]),
            ([0x00, 0x00, 0xd0], [3328, 0]),
            ([0x00, 0x0d, 0x00], [0, 3328]),
            ([0x01, 0xf0, 0xcf], [3327, 1]),
        ] {
            let row = assigned(bytes);
            assert!(evaluate(&row).is_ok());

            for (bits, difference) in row[27..].as_chunks::<12>().0.iter().zip(expected) {
                for (bit, value) in bits.iter().enumerate() {
                    assert_eq!(*value, Goldilocks::from_bool(difference & (1 << bit) != 0));
                }
            }
        }
    }

    /// Every twelve bit value is accepted exactly below the modulus in both packing positions.
    #[test]
    fn all_coefficient_encodings_enforce_the_integer_bound() {
        for coefficient in 0..4096 {
            for (first, second) in [(coefficient, 3328), (3328, coefficient)] {
                let row = forged_pair(first, second);
                assert_eq!(evaluate(&row).is_ok(), coefficient <= 3328);

                if coefficient <= 3328 {
                    assert_eq!(assigned(encoded_pair(first, second)), row);
                }
            }
        }
    }

    /// Native full-key import agrees with every pair encoding and polynomial boundary.
    #[cfg(feature = "prover")]
    #[test]
    fn coefficient_constraints_match_native_key_import() {
        let mut key = [0_u8; 1568];
        key[1536..].fill(255);
        for coefficient in 0..4096 {
            for pair in [
                encoded_pair(coefficient, 3328),
                encoded_pair(3328, coefficient),
            ] {
                key[..3].copy_from_slice(&pair);
                let native = MlKem1024EncapsulationKey::try_from(
                    &EncodedMlKem1024PublicKey::from_bytes(key),
                );
                assert_eq!(native.is_ok(), coefficient <= 3328);
            }
        }

        key[..3].fill(0);
        for offset in (0..1536).step_by(3) {
            for pair in [[0x01, 0x0d, 0x00], [0x00, 0x10, 0xd0]] {
                key[offset..offset + 3].copy_from_slice(&pair);
                assert!(
                    MlKem1024EncapsulationKey::try_from(&EncodedMlKem1024PublicKey::from_bytes(
                        key
                    ),)
                    .is_err()
                );
            }

            key[offset..offset + 3].fill(0);
        }

        for (index, pair) in key[..1536].as_chunks_mut::<3>().0.iter_mut().enumerate() {
            *pair = encoded_pair((index * 17 % 3329) as u16, (index * 31 % 3329) as u16);
            assert!(evaluate(&assigned(*pair)).is_ok());
        }

        let encoded = EncodedMlKem1024PublicKey::from_bytes(key);
        assert_eq!(
            MlKem1024EncapsulationKey::try_from(&encoded)
                .unwrap()
                .to_encoded(),
            encoded
        );
    }

    /// Validation precedence and atomic errors cover both coefficients and every source byte.
    #[test]
    fn invalid_inputs_leave_all_destinations_unchanged() {
        for pair in [[0x01, 0x0d, 0x00], [0x00, 0x10, 0xd0], [255, 255, 255]] {
            let values = pair.map(Goldilocks::from_u8);
            let mut row = [Goldilocks::NEG_ONE; 51];
            assert_eq!(
                RecipientPairAir::assign_row(&values, &mut row),
                Err(RecipientKeyError::NonCanonicalCoefficient)
            );
            assert_eq!(row, [Goldilocks::NEG_ONE; 51]);

            for index in 0..3 {
                for invalid in [Goldilocks::from_u16(256), Goldilocks::NEG_ONE] {
                    let mut changed = values;
                    changed[index] = invalid;
                    assert_eq!(
                        RecipientPairAir::assign_row(&changed, &mut row),
                        Err(RecipientKeyError::InvalidByte)
                    );
                    assert_eq!(row, [Goldilocks::NEG_ONE; 51]);
                }
            }
        }
    }

    /// No source cell, byte bit or difference bit can be changed independently.
    #[test]
    fn every_trace_cell_is_constrained() {
        let row = assigned([0x01, 0xf0, 0xcf]);
        for index in 0..51 {
            let mut forged = row;
            forged[index] += Goldilocks::ONE;
            assert!(!evaluate(&forged).is_ok(), "unconstrained cell {index}");
        }
    }

    /// A negative difference cannot satisfy an invalid coefficient by field arithmetic alone.
    #[test]
    fn negative_difference_cannot_hide_noncanonical_coefficients() {
        for (slot, pair) in [(0, (3329, 0)), (1, (0, 3329))] {
            let mut row = forged_pair(pair.0, pair.1);
            row[27 + slot * 12..39 + slot * 12].fill(Goldilocks::ZERO);
            row[27 + slot * 12] = Goldilocks::NEG_ONE;
            assert!(!evaluate(&row).is_ok());
        }
    }

    /// Matching reconstruction and bound equalities cannot replace Boolean byte bits.
    #[test]
    fn coordinated_nonboolean_bits_and_field_aliases_are_rejected() {
        for (value, difference) in [
            (Goldilocks::TWO, 3326_u16),
            (Goldilocks::from_u16(256), 3072),
            (Goldilocks::NEG_ONE, 3329),
        ] {
            let mut row = forged_pair(0, 0);
            row[0] = value;
            row[3] = value;
            for bit in 0..12 {
                row[27 + bit] = Goldilocks::from_bool(difference & (1 << bit) != 0);
            }

            assert!(!evaluate(&row).is_ok());
        }
    }
}
