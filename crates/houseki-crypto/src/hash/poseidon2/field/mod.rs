//! Protected field arithmetic for the fixed Goldilocks modulus.
//!
//! Numeric operations use the provider's constant time interfaces, while parameter generation
//! depends only on the public modulus and is evaluated at compile time.

mod modulus;

use crypto_bigint::{U64, modular::ConstMontyForm};
use modulus::GoldilocksModulus;
use zeroize::{Zeroize, Zeroizing};

/// Provider representation used only inside guarded field storage.
type Residue = ConstMontyForm<GoldilocksModulus, { U64::LIMBS }>;

/// An owned field value whose storage is cleared when dropped.
///
/// Arithmetic borrows its operands and creates a separate guarded result, keeping field
/// values free of cloning, formatting and equality interfaces.
///
/// Guards clear owned residues and conversion buffers on normal return and unwinding, but
/// cannot erase borrowed inputs or every compiler, register or system copy.
pub(super) struct FieldElement {
    /// Montgomery residue cleared before its owned storage is released.
    value: Zeroizing<Residue>,
}

impl FieldElement {
    /// Interprets a borrowed integer modulo the fixed field order.
    ///
    /// Every u64 is accepted as an arithmetic input, so this operation must not replace
    /// canonical byte decoding or the sponge's bounded byte packing.
    pub(super) fn from_word(word: &u64) -> Self {
        let integer = Zeroizing::new(U64::from_u64(*word));

        Self {
            value: Zeroizing::new(Residue::new(&integer)),
        }
    }

    /// Returns the canonical integer in guarded storage.
    pub(super) fn canonical_word(&self) -> Zeroizing<u64> {
        let integer = Zeroizing::new(self.value.retrieve());
        Zeroizing::new(u64::from(*integer))
    }

    /// Returns the modular sum without changing either operand.
    pub(super) fn add(&self, rhs: &Self) -> Self {
        Self {
            value: Zeroizing::new(self.value.add(&rhs.value)),
        }
    }

    /// Returns the modular product without changing either operand.
    pub(super) fn multiply(&self, rhs: &Self) -> Self {
        Self {
            value: Zeroizing::new(self.value.mul(&rhs.value)),
        }
    }

    /// Returns the modular square without changing the operand.
    pub(super) fn square(&self) -> Self {
        Self {
            value: Zeroizing::new(self.value.square()),
        }
    }
}

impl Default for FieldElement {
    /// Creates an owned zero field value.
    fn default() -> Self {
        Self {
            value: Zeroizing::new(Residue::ZERO),
        }
    }
}

impl Zeroize for FieldElement {
    /// Clears the stored residue while leaving a usable zero field value.
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

/// Numeric conversion, modular arithmetic and explicit storage clearing.
#[cfg(test)]
mod tests {
    use super::{FieldElement, Zeroize};

    /// Independent modulus used by the wide integer reference calculations.
    const MODULUS: u128 = (1_u128 << 64) - (1_u128 << 32) + 1;

    /// Values spanning packed words, product carries and noncanonical integers.
    const WORDS: [u64; 12] = [
        0,
        1,
        2,
        (1 << 32) - 1,
        1 << 32,
        1 << 48,
        (1 << 56) - 1,
        1 << 63,
        0xffff_fffe_ffff_ffff,
        0xffff_ffff_0000_0000,
        0xffff_ffff_0000_0001,
        u64::MAX,
    ];

    /// Checks canonical conversion without treating modular reduction as a byte codec.
    #[test]
    fn integer_import_returns_canonical_residues() {
        for word in WORDS {
            let field = FieldElement::from_word(&word);

            assert_eq!(
                u128::from(*field.canonical_word()),
                u128::from(word) % MODULUS
            );
        }

        assert_eq!(*FieldElement::default().canonical_word(), 0);
    }

    /// Checks addition across the field order and machine word overflow boundaries.
    #[test]
    fn sums_match_wide_integer_remainders_without_changing_operands() {
        for left in WORDS {
            for right in WORDS {
                let a = FieldElement::from_word(&left);
                let b = FieldElement::from_word(&right);
                let expected = (u128::from(left) + u128::from(right)) % MODULUS;

                assert_eq!(u128::from(*a.add(&b).canonical_word()), expected);
                assert_eq!(u128::from(*a.canonical_word()), u128::from(left) % MODULUS);
                assert_eq!(u128::from(*b.canonical_word()), u128::from(right) % MODULUS);
            }
        }
    }

    /// Checks multiplication with full width products and reduction carries.
    #[test]
    fn products_match_wide_integer_remainders_without_changing_operands() {
        for left in WORDS {
            for right in WORDS {
                let a = FieldElement::from_word(&left);
                let b = FieldElement::from_word(&right);
                let expected = (u128::from(left) * u128::from(right)) % MODULUS;

                assert_eq!(u128::from(*a.multiply(&b).canonical_word()), expected);
                assert_eq!(u128::from(*a.canonical_word()), u128::from(left) % MODULUS);
                assert_eq!(u128::from(*b.canonical_word()), u128::from(right) % MODULUS);
            }
        }
    }

    /// Checks composed squaring and multiplication against the seventh power relation.
    #[test]
    fn composed_arithmetic_preserves_the_poseidon_exponent() {
        for word in WORDS {
            let value = FieldElement::from_word(&word);
            let square = value.square();
            let fourth = square.square();
            let seventh = fourth.multiply(&square).multiply(&value);

            let reduced = u128::from(word) % MODULUS;
            let expected = (0..7).fold(1, |acc, _| acc * reduced % MODULUS);

            assert_eq!(
                u128::from(*square.canonical_word()),
                reduced * reduced % MODULUS
            );
            assert_eq!(u128::from(*seventh.canonical_word()), expected);
            assert_eq!(u128::from(*value.canonical_word()), reduced);
        }
    }

    /// Checks that clearing field storage also clears arrays used by future state owners.
    #[test]
    fn explicit_zeroization_clears_residues_and_leaves_usable_zero_values() {
        let mut fields = WORDS.map(|word| FieldElement::from_word(&word));
        fields.zeroize();

        let one = FieldElement::from_word(&1);
        for field in fields {
            assert_eq!(*field.canonical_word(), 0);
            assert_eq!(*field.add(&one).canonical_word(), 1);
        }
    }
}
