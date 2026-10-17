//! Bounded monetary values, expressed in atoms.

mod decimal;
mod error;

pub use error::AmountError;

use zeroize::Zeroize;

/// An exact amount from zero through [`Self::MAX_ATOMS`], stored as atoms.
///
/// Each coin contains [`Self::ATOMS_PER_COIN`] atoms, providing 20 decimal places without
/// floating point arithmetic.
///
/// Parsing and display use coin units, while construction and arithmetic operate on the
/// underlying atom count.
///
/// The bound applies to individual amounts, so conservation calculations may need checked `u128`
/// intermediates for totals that exceed it.
///
/// The ledger remains responsible for enforcing the global supply limit across all amounts.
///
/// Decimal input must contain ASCII whole digits and may include a decimal point followed by 1
/// to 20 fractional digits.
///
/// Leading whole zeroes and trailing fractional zeroes are accepted and normalized when
/// displayed, while signs, whitespace, exponents and digit separators are rejected.
///
/// [`Zeroize::zeroize`] clears the stored atom count to zero, allowing private owners to use
/// [`zeroize::Zeroizing`] while retaining the bounded representation.
///
/// The value remains copyable and is not cleared automatically, so callers remain responsible
/// for independent copies, diagnostics and storage outside a guarded owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(
    /// Exact atom count within the individual amount cap.
    u128,
);

impl Amount {
    /// Number of fractional decimal places in one coin.
    pub const DECIMAL_PLACES: u32 = 20;

    /// One coin contains `10^20` atoms.
    pub const ATOMS_PER_COIN: u128 = 10_u128.pow(Self::DECIMAL_PLACES);

    /// The maximum number of coins is one billion.
    pub const MAX_COINS: u128 = 1_000_000_000;

    /// An amount can contain at most `10^29` atoms.
    pub const MAX_ATOMS: u128 = Self::ATOMS_PER_COIN * Self::MAX_COINS;

    /// Constructs an amount from an atom count within the protocol limit.
    ///
    /// Zero remains representable for balances, fees and arithmetic results, while ordinary
    /// note consumers require a positive amount.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::ValueExceedsMaximum`] if the atom count exceeds
    /// [`Self::MAX_ATOMS`].
    pub const fn from_atoms(atoms: u128) -> Result<Self, AmountError> {
        if atoms > Self::MAX_ATOMS {
            return Err(AmountError::ValueExceedsMaximum);
        }

        Ok(Self(atoms))
    }

    /// Returns the exact atom count.
    pub const fn atoms(&self) -> u128 {
        self.0
    }

    /// Adds two amounts and checks that their sum stays within the protocol limit.
    ///
    /// Use checked `u128` arithmetic for conservation calculations whose
    /// intermediate totals may exceed [`Self::MAX_ATOMS`].
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::ValueExceedsMaximum`] if the sum exceeds
    /// [`Self::MAX_ATOMS`].
    pub const fn checked_add(self, rhs: Self) -> Result<Self, AmountError> {
        match self.0.checked_add(rhs.0) {
            Some(atoms) => Self::from_atoms(atoms),
            None => Err(AmountError::ValueOverflow),
        }
    }

    /// Subtracts an amount without wrapping or saturating.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::ValueUnderflow`] if `rhs` exceeds this amount.
    pub const fn checked_sub(self, rhs: Self) -> Result<Self, AmountError> {
        match self.0.checked_sub(rhs.0) {
            Some(atoms) => Ok(Self(atoms)),
            None => Err(AmountError::ValueUnderflow),
        }
    }

    /// Encodes the atom count as exactly 16 little endian bytes.
    pub const fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Decodes an atom count from exactly 16 little endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::ValueExceedsMaximum`] if the decoded atom count
    /// exceeds [`Self::MAX_ATOMS`].
    pub const fn from_le_bytes(bytes: [u8; 16]) -> Result<Self, AmountError> {
        Self::from_atoms(u128::from_le_bytes(bytes))
    }
}

impl Zeroize for Amount {
    /// Clears this value's atom count to the valid zero amount.
    ///
    /// This changes only the borrowed storage and does not clear independent copies.
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl TryFrom<&[u8]> for Amount {
    /// Error returned when the slice has an invalid length or exceeds the amount cap.
    type Error = AmountError;

    /// Decodes an amount from a slice containing exactly 16 little endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::InvalidByteLength`] if the slice is shorter or
    /// longer than 16 bytes, or [`AmountError::ValueExceedsMaximum`] if the
    /// decoded atom count exceeds the protocol limit.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes
            .try_into()
            .map_err(|_| AmountError::InvalidByteLength {
                actual: bytes.len(),
            })?;

        Self::from_le_bytes(bytes)
    }
}

/// Construction, conversion and rejection properties of [`Amount`].
#[cfg(test)]
mod tests {
    use zeroize::{Zeroize, Zeroizing};

    use super::{Amount, AmountError};

    /// Checks that explicit clearing handles both integer halves and retains a valid amount.
    #[test]
    fn zeroization_clears_live_values_to_a_valid_zero() {
        let zero = Amount::from_atoms(0).unwrap();

        for atoms in [
            0,
            1,
            u128::from(u64::MAX),
            1_u128 << 64,
            1_u128 << 96,
            Amount::MAX_ATOMS,
        ] {
            let mut amount = Amount::from_atoms(atoms).unwrap();
            amount.zeroize();

            assert_eq!(amount, zero);
        }
    }

    /// Checks guarded typed borrowing and clearing without changing an independent copy.
    #[test]
    fn zeroizing_storage_retains_typed_borrowing_and_clears_only_its_value() {
        let original = Amount::from_atoms(Amount::MAX_ATOMS).unwrap();
        let mut guarded = Zeroizing::new(original);
        let borrowed: &Amount = &guarded;

        assert_eq!(borrowed.atoms(), Amount::MAX_ATOMS);

        guarded.zeroize();

        assert_eq!(guarded.atoms(), 0);
        assert_eq!(original.atoms(), Amount::MAX_ATOMS);
    }

    /// Checks that construction accepts the monetary range.
    #[test]
    fn construction_accepts_the_monetary_range() {
        for atoms in [0, 1, 10_u128.pow(20), 10_u128.pow(29)] {
            assert_eq!(Amount::from_atoms(atoms).unwrap().atoms(), atoms);
        }
    }

    /// Checks that construction rejects values above the exact cap.
    #[test]
    fn construction_rejects_values_above_the_exact_cap() {
        for atoms in [10_u128.pow(29) + 1, (1_u128 << 97) - 1, u128::MAX] {
            assert!(matches!(
                Amount::from_atoms(atoms),
                Err(AmountError::ValueExceedsMaximum)
            ));
        }
    }

    /// Checks that construction checks the cap in const contexts.
    #[test]
    fn construction_checks_the_cap_in_const_contexts() {
        /// Smallest positive amount constructed at compile time.
        const ONE_ATOM: Amount = match Amount::from_atoms(1) {
            Ok(amount) => amount,
            Err(_) => panic!("one atom is valid"),
        };

        /// Compile time atom count of the smallest positive amount.
        const ATOMS: u128 = ONE_ATOM.atoms();

        /// Compile time rejection of an amount above the exact cap.
        const TOO_LARGE: Result<Amount, AmountError> = Amount::from_atoms(10_u128.pow(29) + 1);

        assert_eq!(ATOMS, 1);
        assert!(matches!(TOO_LARGE, Err(AmountError::ValueExceedsMaximum)));
    }

    /// Checks that addition preserves valid sums across carries.
    #[test]
    fn addition_preserves_valid_sums_across_carries() {
        for (left, right, expected) in [
            (0, 0, 0),
            (2, 3, 5),
            (65_535, 1, 65_536),
            (u64::MAX as u128, 1, 1_u128 << 64),
            (10_u128.pow(29) - 1, 1, 10_u128.pow(29)),
            (10_u128.pow(29), 0, 10_u128.pow(29)),
        ] {
            let left = Amount::from_atoms(left).unwrap();
            let right = Amount::from_atoms(right).unwrap();

            assert_eq!(left.checked_add(right).unwrap().atoms(), expected);
        }
    }

    /// Checks that addition rejects sums above the cap.
    #[test]
    fn addition_rejects_sums_above_the_cap() {
        let maximum = Amount::from_atoms(10_u128.pow(29)).unwrap();

        for right in [Amount::from_atoms(1).unwrap(), maximum] {
            assert!(matches!(
                maximum.checked_add(right),
                Err(AmountError::ValueExceedsMaximum)
            ));
        }
    }

    /// Checks that subtraction preserves valid differences across borrows.
    #[test]
    fn subtraction_preserves_valid_differences_across_borrows() {
        for (left, right, expected) in [
            (0, 0, 0),
            (3, 2, 1),
            (65_536, 1, 65_535),
            (1_u128 << 64, 1, u64::MAX as u128),
            (10_u128.pow(29), 0, 10_u128.pow(29)),
            (10_u128.pow(29), 10_u128.pow(29), 0),
        ] {
            let left = Amount::from_atoms(left).unwrap();
            let right = Amount::from_atoms(right).unwrap();

            assert_eq!(left.checked_sub(right).unwrap().atoms(), expected);
        }
    }

    /// Checks that subtraction rejects negative results.
    #[test]
    fn subtraction_rejects_negative_results() {
        for (left, right) in [(0, 1), (10_u128.pow(29) - 1, 10_u128.pow(29))] {
            let left = Amount::from_atoms(left).unwrap();
            let right = Amount::from_atoms(right).unwrap();

            assert!(matches!(
                left.checked_sub(right),
                Err(AmountError::ValueUnderflow)
            ));
        }
    }

    /// Checks that decimal conversion preserves exact atoms and normalizes display.
    #[test]
    fn decimal_conversion_preserves_exact_atoms_and_normalizes_display() {
        for (input, expected_atoms, expected_display) in [
            ("0", 0, "0"),
            ("000.000", 0, "0"),
            ("1", 10_u128.pow(20), "1"),
            ("0001.2300", 123_000_000_000_000_000_000, "1.23"),
            ("0.00000000000000000001", 1, "0.00000000000000000001"),
            (
                "12.34000000000000000001",
                1_234_000_000_000_000_000_001,
                "12.34000000000000000001",
            ),
            (
                "999999999.99999999999999999999",
                10_u128.pow(29) - 1,
                "999999999.99999999999999999999",
            ),
            (
                "1000000000.00000000000000000000",
                10_u128.pow(29),
                "1000000000",
            ),
        ] {
            let amount = input.parse::<Amount>().unwrap();

            assert_eq!(amount.atoms(), expected_atoms, "{input}");
            assert_eq!(amount.to_string(), expected_display, "{input}");
            assert_eq!(amount.to_string().parse::<Amount>().unwrap(), amount);
        }
    }

    /// Checks that decimal parsing rejects malformed or ambiguous text.
    #[test]
    fn decimal_parsing_rejects_malformed_or_ambiguous_text() {
        for input in [
            "", " ", " 1", "1 ", "+1", "-0", "-1", "1e2", "1_000", "1,0", ".1", "1.", "1..0",
            "NaN", "inf", "１", "١", "1.٢", "0x1", "\n1",
        ] {
            assert!(
                matches!(input.parse::<Amount>(), Err(AmountError::InvalidDecimal)),
                "{input:?}"
            );
        }
    }

    /// Checks that decimal parsing rejects excess precision without rounding.
    #[test]
    fn decimal_parsing_rejects_excess_precision_without_rounding() {
        for input in ["0.000000000000000000001", "1.000000000000000000000"] {
            assert!(matches!(
                input.parse::<Amount>(),
                Err(AmountError::TooManyDecimalPlaces)
            ));
        }
    }

    /// Checks that decimal parsing rejects values above the cap.
    #[test]
    fn decimal_parsing_rejects_values_above_the_cap() {
        for input in ["1000000001", "1000000000.00000000000000000001"] {
            assert!(matches!(
                input.parse::<Amount>(),
                Err(AmountError::ValueExceedsMaximum)
            ));
        }
    }

    /// Checks that decimal parsing reports integer overflow without panicking.
    #[test]
    fn decimal_parsing_reports_integer_overflow_without_panicking() {
        for input in [
            "340282366920938463463374607431768211455",
            "340282366920938463463374607431768211456",
            "3402823669209384634.63374607431768211456",
        ] {
            assert!(matches!(
                input.parse::<Amount>(),
                Err(AmountError::ValueOverflow)
            ));
        }
    }

    /// Checks that byte encoding matches little endian fixtures.
    #[test]
    fn byte_encoding_matches_little_endian_fixtures() {
        for (atoms, bytes) in [
            (0, [0; 16]),
            (1, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (256, [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (
                0x0102_0304_0506_0708_090a_0b0c,
                [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0],
            ),
        ] {
            assert_eq!(Amount::from_atoms(atoms).unwrap().to_le_bytes(), bytes);
            assert_eq!(Amount::from_le_bytes(bytes).unwrap().atoms(), atoms);
            assert_eq!(Amount::try_from(bytes.as_slice()).unwrap().atoms(), atoms);
        }
    }

    /// Checks that byte decoding enforces the exact cap.
    #[test]
    fn byte_decoding_enforces_the_exact_cap() {
        let maximum_bytes = 10_u128.pow(29).to_le_bytes();

        assert_eq!(
            Amount::from_le_bytes(maximum_bytes).unwrap().atoms(),
            10_u128.pow(29)
        );

        for atoms in [10_u128.pow(29) + 1, (1_u128 << 97) - 1, u128::MAX] {
            let bytes = atoms.to_le_bytes();

            assert!(matches!(
                Amount::from_le_bytes(bytes),
                Err(AmountError::ValueExceedsMaximum)
            ));
            assert!(matches!(
                Amount::try_from(bytes.as_slice()),
                Err(AmountError::ValueExceedsMaximum)
            ));
        }
    }

    /// Checks that byte decoding rejects truncated and trailing bytes.
    #[test]
    fn byte_decoding_rejects_truncated_and_trailing_bytes() {
        for length in [0, 1, 15, 17, 32] {
            let bytes = vec![0; length];

            assert!(matches!(
                Amount::try_from(bytes.as_slice()),
                Err(AmountError::InvalidByteLength { actual }) if actual == length
            ));
        }
    }

    /// Checks that byte encoding is available in const contexts.
    #[test]
    fn byte_encoding_is_available_in_const_contexts() {
        /// Zero amount decoded at compile time.
        const ZERO: Amount = match Amount::from_le_bytes([0; 16]) {
            Ok(amount) => amount,
            Err(_) => panic!("zero is valid"),
        };

        /// Canonical zero amount bytes produced at compile time.
        const BYTES: [u8; 16] = ZERO.to_le_bytes();

        assert_eq!(BYTES, [0; 16]);
    }
}
