//! Complete occupied leaf counts including the full depth 64 tree.

mod error;

pub use error::NoteCountError;

use crate::NotePosition;

/// A public occupied leaf count from zero through 2^64 inclusive.
///
/// A count does not establish that an anchor exists or authenticates any actual leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoteCount(
    /// Bounded integer wide enough to represent the full tree rather than only its last position.
    u128,
);

impl NoteCount {
    /// Number of leaves in the adopted binary depth 64 application tree.
    pub const CAPACITY: u128 = 1_u128 << 64;

    /// Checks that the complete occupied count fits the fixed tree capacity.
    ///
    /// # Errors
    ///
    /// Returns [`NoteCountError`] for every value greater than 2^64.
    pub const fn new(value: u128) -> Result<Self, NoteCountError> {
        if value > Self::CAPACITY {
            return Err(NoteCountError);
        }

        Ok(Self(value))
    }

    /// Returns the complete public count without narrowing its full capacity value.
    pub const fn value(&self) -> u128 {
        self.0
    }

    /// Advances an occupied count without wrapping or exceeding tree capacity.
    pub const fn checked_next(self) -> Option<Self> {
        if self.0 == Self::CAPACITY {
            None
        } else {
            Some(Self(self.0 + 1))
        }
    }

    /// Returns the next append position, or none when all 2^64 positions are occupied.
    pub fn next_position(&self) -> Option<NotePosition> {
        u64::try_from(self.0).ok().map(NotePosition::new)
    }
}

/// Exact capacity, final position and checked append exhaustion.
#[cfg(test)]
mod tests {
    use crate::{NoteCount, NotePosition};

    /// Preserves the full count range while distinguishing the last leaf from a full tree.
    #[test]
    fn note_counts_represent_full_capacity_and_checked_positions() {
        for count in [0, 1, (1_u128 << 32) + 1, u128::from(u64::MAX)] {
            let value = NoteCount::new(count).unwrap();

            assert_eq!(value.value(), count);
            assert_eq!(
                value.next_position(),
                Some(NotePosition::new(u64::try_from(count).unwrap()))
            );
            assert_eq!(value.checked_next().unwrap().value(), count + 1);
        }

        let full = NoteCount::new(1_u128 << 64).unwrap();

        assert_eq!(full.value(), 1_u128 << 64);
        assert_eq!(full.next_position(), None);
        assert_eq!(full.checked_next(), None);

        for invalid in [(1_u128 << 64) + 1, u128::MAX] {
            assert!(NoteCount::new(invalid).is_err());
        }
    }
}
