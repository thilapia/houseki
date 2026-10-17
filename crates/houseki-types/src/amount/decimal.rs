//! Exact decimal conversion in coin units.

use super::{Amount, AmountError};
use core::{fmt, str::FromStr};

impl FromStr for Amount {
    /// Error returned when decimal amount text cannot be parsed exactly.
    type Err = AmountError;

    /// Parses an exact coin value from an unsigned decimal string.
    ///
    /// The whole part must contain ASCII digits and may be followed by a decimal point and 1 to
    /// 20 fractional digits.
    ///
    /// Leading whole zeroes and trailing fractional zeroes are accepted, while signs,
    /// whitespace, exponents and digit separators are rejected.
    ///
    /// Values are never rounded, and the limit of 20 fractional digits applies
    /// even when the extra digits are zero.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (whole, fraction) = match input.split_once('.') {
            Some((_, "")) => return Err(AmountError::InvalidDecimal),
            Some(parts) => parts,
            None => (input, ""),
        };

        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(AmountError::InvalidDecimal);
        }

        if fraction.len() > Self::DECIMAL_PLACES as usize {
            return Err(AmountError::TooManyDecimalPlaces);
        }

        let whole = whole
            .parse::<u128>()
            .map_err(|_| AmountError::ValueOverflow)?;

        let fractional_atoms = if fraction.is_empty() {
            0
        } else {
            let digits = fraction
                .parse::<u128>()
                .map_err(|_| AmountError::ValueOverflow)?;

            // At most 20 decimal digits, so this product is below one coin.
            digits * 10_u128.pow(Self::DECIMAL_PLACES - fraction.len() as u32)
        };

        let atoms = whole
            .checked_mul(Self::ATOMS_PER_COIN)
            .and_then(|atoms| atoms.checked_add(fractional_atoms))
            .ok_or(AmountError::ValueOverflow)?;

        Self::from_atoms(atoms)
    }
}

impl fmt::Display for Amount {
    /// Formats the exact coin value, omitting redundant fractional zeroes.
    ///
    /// The full monetary value is preserved regardless of formatter precision,
    /// so formatting never rounds or truncates the amount.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.atoms() / Self::ATOMS_PER_COIN;
        let mut fraction = self.atoms() % Self::ATOMS_PER_COIN;
        if fraction == 0 {
            return write!(formatter, "{whole}");
        }

        let mut width = Self::DECIMAL_PLACES as usize;
        while fraction.is_multiple_of(10) {
            fraction /= 10;
            width -= 1;
        }

        write!(formatter, "{whole}.{fraction:0width$}")
    }
}
