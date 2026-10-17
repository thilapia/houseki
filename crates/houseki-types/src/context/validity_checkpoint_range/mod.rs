//! Inclusive checkpoint bounds for transaction validity.

mod error;

pub use error::ValidityCheckpointRangeError;

use super::CheckpointSequence;

/// A transaction validity window that includes both endpoint checkpoints.
///
/// The start must be no later than the end.
///
/// Equal endpoints restrict the window to one checkpoint, and either endpoint can use any
/// representable sequence.
///
/// Membership checks only whether a sequence lies within these bounds.
///
/// Execution remains responsible for selecting the current checkpoint and checking the
/// transaction's other requirements, including its anchor and proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidityCheckpointRange {
    /// Inclusive first checkpoint sequence at which the transaction may execute.
    start: CheckpointSequence,

    /// Inclusive last checkpoint sequence, never before the start.
    end: CheckpointSequence,
}

impl ValidityCheckpointRange {
    /// Constructs a validity window including both `start` and `end`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidityCheckpointRangeError::ReversedBounds`] if `start` is
    /// after `end`.
    pub const fn new(
        start: CheckpointSequence,
        end: CheckpointSequence,
    ) -> Result<Self, ValidityCheckpointRangeError> {
        if start.value() > end.value() {
            return Err(ValidityCheckpointRangeError::ReversedBounds);
        }

        Ok(Self { start, end })
    }

    /// Returns the first checkpoint included in the window.
    pub const fn start(&self) -> CheckpointSequence {
        self.start
    }

    /// Returns the last checkpoint included in the window.
    pub const fn end(&self) -> CheckpointSequence {
        self.end
    }

    /// Reports whether `sequence` lies within the inclusive checkpoint bounds.
    pub const fn contains(&self, sequence: CheckpointSequence) -> bool {
        self.start.value() <= sequence.value() && sequence.value() <= self.end.value()
    }
}

/// Construction, conversion and rejection properties of [`ValidityCheckpointRange`].
#[cfg(test)]
mod tests {
    use super::{CheckpointSequence, ValidityCheckpointRange, ValidityCheckpointRangeError};

    /// Checks that construction rejects reversed bounds.
    #[test]
    fn construction_rejects_reversed_bounds() {
        for (start, end) in [(1, 0), (u64::MAX, 0), (u64::MAX, u64::MAX - 1)] {
            assert!(matches!(
                ValidityCheckpointRange::new(
                    CheckpointSequence::new(start),
                    CheckpointSequence::new(end),
                ),
                Err(ValidityCheckpointRangeError::ReversedBounds)
            ));
        }
    }

    /// Checks that membership includes both endpoints and rejects outside sequences.
    #[test]
    fn membership_includes_both_endpoints_and_rejects_outside_sequences() {
        let range =
            ValidityCheckpointRange::new(CheckpointSequence::new(10), CheckpointSequence::new(20))
                .unwrap();

        for (sequence, expected) in [(9, false), (10, true), (15, true), (20, true), (21, false)] {
            assert_eq!(range.contains(CheckpointSequence::new(sequence)), expected);
        }
    }

    /// Checks that equal endpoints restrict validity to one checkpoint.
    #[test]
    fn equal_endpoints_restrict_validity_to_one_checkpoint() {
        for value in [0, 42, u64::MAX] {
            let sequence = CheckpointSequence::new(value);
            let range = ValidityCheckpointRange::new(sequence, sequence).unwrap();

            assert_eq!(range.start(), sequence);
            assert_eq!(range.end(), sequence);
            assert!(range.contains(sequence));

            if let Some(previous) = value.checked_sub(1) {
                assert!(!range.contains(CheckpointSequence::new(previous)));
            }
            if let Some(next) = value.checked_add(1) {
                assert!(!range.contains(CheckpointSequence::new(next)));
            }
        }
    }

    /// Checks that full sequence range includes the maximum without overflow.
    #[test]
    fn full_sequence_range_includes_the_maximum_without_overflow() {
        let range = ValidityCheckpointRange::new(
            CheckpointSequence::new(0),
            CheckpointSequence::new(u64::MAX),
        )
        .unwrap();

        for value in [0, 1, 4_294_967_296, u64::MAX] {
            assert!(range.contains(CheckpointSequence::new(value)));
        }
    }

    /// Checks that validity can be checked in const contexts.
    #[test]
    fn validity_can_be_checked_in_const_contexts() {
        /// Inclusive checkpoint fixture constructed at compile time.
        const RANGE: ValidityCheckpointRange = match ValidityCheckpointRange::new(
            CheckpointSequence::new(7),
            CheckpointSequence::new(9),
        ) {
            Ok(range) => range,
            Err(_) => panic!("ordered bounds are valid"),
        };
        /// Compile time first sequence of the validity fixture.
        const START: u64 = RANGE.start().value();
        /// Compile time last sequence of the validity fixture.
        const END: u64 = RANGE.end().value();
        /// Compile time membership result for a sequence inside the fixture.
        const INCLUDED: bool = RANGE.contains(CheckpointSequence::new(8));
        /// Compile time membership result for a sequence outside the fixture.
        const EXCLUDED: bool = RANGE.contains(CheckpointSequence::new(10));

        assert_eq!((START, END, INCLUDED, EXCLUDED), (7, 9, true, false));
    }
}
