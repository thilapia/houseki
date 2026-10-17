//! Guarded exact integer totals for future native payment conservation checks.
//!
//! On the supported 64 bit hosts, a list count fits `usize`, so at most `2^64` bounded
//! amounts including the separate fee have a sum below `2^161` atoms.
//!
//! The private 256 bit storage leaves room above that bound without selecting a wire format,
//! AIR representation or protocol count limit, and checked addition prevents silent overflow.

use crypto_bigint::{Limb, U256, ctutils::CtEq};
use houseki_types::Amount;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// A private exact total whose owned integer storage is cleared when dropped.
///
/// Addend and candidate sum storage are also guarded through success, failure and unwinding.
///
/// Cleanup cannot erase every copy created by the backend, compiler or operating system.
///
/// Callers retain responsibility for source amount cleanup, actual list bounds, ordinary note
/// rules and adding the public fee exactly once on the output side.
///
/// Comparing totals establishes only integer equality, without checking note correspondence,
/// commitments, membership or a complete payment relation.
pub(crate) struct AmountTotal {
    /// Guarded full width sum without an ordinary diagnostic or byte export.
    value: Zeroizing<U256>,
}

impl AmountTotal {
    /// Creates an empty exact total in guarded storage.
    pub(crate) fn zero() -> Self {
        Self {
            value: Zeroizing::new(U256::ZERO),
        }
    }

    /// Adds a borrowed bounded amount without consuming its original storage.
    ///
    /// Zero remains a valid addend for fees and arithmetic even though ordinary notes are positive.
    ///
    /// # Errors
    ///
    /// Returns [`AmountTotalError::Overflow`] without changing the total if the exact sum exceeds
    /// the private integer capacity, with no rejected amount or partial sum included in the error.
    pub(crate) fn add_amount(&mut self, amount: &Amount) -> Result<(), AmountTotalError> {
        let addend = Zeroizing::new(U256::from_u128(amount.atoms()));
        let candidate = Zeroizing::new(self.value.carrying_add(&addend, Limb::ZERO));
        let (sum, carry) = &*candidate;
        if *carry != Limb::ZERO {
            return Err(AmountTotalError::Overflow);
        }

        *self.value = *sum;

        Ok(())
    }

    /// Compares every integer limb through the pinned dependency's equality operation.
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.value.ct_eq(&other.value).into()
    }
}

impl fmt::Debug for AmountTotal {
    /// Writes a fixed redacted label without inspecting the private total.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AmountTotal([REDACTED])")
    }
}

/// A failure to retain an exact total within the private integer capacity.
#[derive(Debug, Error)]
pub(crate) enum AmountTotalError {
    /// Addition would exceed the full width sum without producing a usable replacement.
    #[error("amount total overflow")]
    Overflow,
}

/// Exact totals, independent carry vectors, capacity failure and private diagnostic behavior.
#[cfg(test)]
mod tests {
    use crypto_bigint::U256;
    use houseki_types::Amount;
    use zeroize::Zeroizing;

    use super::{AmountTotal, AmountTotalError};

    /// Seeds a protected partial total from a fixed public hexadecimal test vector.
    fn partial_total(hex: &str) -> AmountTotal {
        AmountTotal {
            value: Zeroizing::new(U256::from_be_hex(hex)),
        }
    }

    /// Checks empty totals, zero fees and bounded additions preserve borrowed source amounts.
    #[test]
    fn bounded_amounts_accumulate_exactly_from_zero() {
        let mut total = AmountTotal::zero();
        assert_eq!(*total.value, U256::ZERO);

        let zero = Amount::from_atoms(0).unwrap();
        total.add_amount(&zero).unwrap();
        assert_eq!(*total.value, U256::ZERO);

        let first = Amount::from_atoms(2).unwrap();
        let second = Amount::from_atoms(3).unwrap();
        total.add_amount(&first).unwrap();
        total.add_amount(&second).unwrap();

        assert_eq!(*total.value, U256::from_u128(5));
        assert_eq!(first.atoms(), 2);
        assert_eq!(second.atoms(), 3);
    }

    /// Checks fixed independent vectors carry across every 64 bit boundary without narrowing.
    #[test]
    fn addition_preserves_carries_beyond_the_amount_and_u128_ranges() {
        let one = Amount::from_atoms(1).unwrap();
        for (initial, expected) in [
            (
                concat!(
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000",
                    "ffffffffffffffff"
                ),
                concat!(
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000001",
                    "0000000000000000"
                ),
            ),
            (
                concat!(
                    "0000000000000000",
                    "0000000000000000",
                    "ffffffffffffffff",
                    "ffffffffffffffff"
                ),
                concat!(
                    "0000000000000000",
                    "0000000000000001",
                    "0000000000000000",
                    "0000000000000000"
                ),
            ),
            (
                concat!(
                    "0000000000000000",
                    "ffffffffffffffff",
                    "ffffffffffffffff",
                    "ffffffffffffffff"
                ),
                concat!(
                    "0000000000000001",
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000"
                ),
            ),
        ] {
            let mut total = partial_total(initial);

            total.add_amount(&one).unwrap();

            assert_eq!(*total.value, U256::from_be_hex(expected));
        }
    }

    /// Checks the maximum 64 bit note count plus a separate maximal fee against integer vectors.
    #[test]
    fn representable_note_counts_and_a_fee_fit_the_exact_total() {
        // Independent Python integer arithmetic computes (2^64 - 1) * 10^29 and 2^64 * 10^29.
        let mut total =
            partial_total("000000000000000000000001431e0fae6d7217c95ce1f051928de83560000000");
        let fee = Amount::from_atoms(Amount::MAX_ATOMS).unwrap();

        total.add_amount(&fee).unwrap();

        assert_eq!(
            *total.value,
            U256::from_be_hex("000000000000000000000001431e0fae6d7217caa00000000000000000000000")
        );
    }

    /// Checks the last valid sum and capacity failure retain the exact previous guarded value.
    #[test]
    fn overflow_leaves_the_previous_total_unchanged_and_usable() {
        // Independent Python integer arithmetic computes 2^256 - 1 - 10^29 for the initial sum.
        let mut total =
            partial_total("fffffffffffffffffffffffffffffffffffffffebce1f051928de8355fffffff");
        let maximum = Amount::from_atoms(Amount::MAX_ATOMS).unwrap();
        total.add_amount(&maximum).unwrap();
        assert_eq!(*total.value, U256::MAX);

        let one = Amount::from_atoms(1).unwrap();
        let error = total.add_amount(&one).unwrap_err();

        assert!(matches!(error, AmountTotalError::Overflow));
        assert_eq!(error.to_string(), "amount total overflow");
        assert_eq!(*total.value, U256::MAX);

        total.add_amount(&Amount::from_atoms(0).unwrap()).unwrap();
        assert_eq!(*total.value, U256::MAX);
    }

    /// Checks equality across distinct addition paths and every position in the complete integer.
    #[test]
    fn comparison_covers_all_256_bits() {
        let mut first = AmountTotal::zero();
        first.add_amount(&Amount::from_atoms(2).unwrap()).unwrap();
        first.add_amount(&Amount::from_atoms(3).unwrap()).unwrap();
        let mut second = AmountTotal::zero();
        second.add_amount(&Amount::from_atoms(5).unwrap()).unwrap();

        assert!(first.matches(&second));
        assert!(second.matches(&first));

        second.add_amount(&Amount::from_atoms(1).unwrap()).unwrap();
        assert!(!first.matches(&second));
        assert!(!second.matches(&first));

        for bit in 0..256 {
            let changed = AmountTotal {
                value: Zeroizing::new(*first.value ^ (U256::ONE << bit)),
            };

            assert!(!first.matches(&changed));
            assert!(!changed.matches(&first));
        }
    }

    /// Checks fixed ordinary and alternate diagnostics across zero, bounded and full width totals.
    #[test]
    fn diagnostics_redact_the_complete_private_total() {
        for value in [U256::ZERO, U256::from_u128(Amount::MAX_ATOMS), U256::MAX] {
            let total = AmountTotal {
                value: Zeroizing::new(value),
            };

            assert_eq!(format!("{total:?}"), "AmountTotal([REDACTED])");
            assert_eq!(format!("{total:#?}"), "AmountTotal([REDACTED])");
        }
    }
}
