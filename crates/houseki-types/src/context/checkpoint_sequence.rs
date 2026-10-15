//! Positions in the checkpoint sequence.

/// A numeric position in the ordered sequence of checkpoints.
///
/// Transaction validity uses checkpoint progression independently of wall time
/// and validator epochs. This value identifies a position but does not establish
/// that the corresponding checkpoint exists or has been finalized.
///
/// Every `u64` value is representable, including zero. Advancement is checked so
/// that exhausting the counter cannot wrap back to an earlier checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointSequence(u64);

impl CheckpointSequence {
    /// Constructs a checkpoint sequence from its numeric value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric checkpoint sequence.
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Returns the next sequence, or `None` when the counter is exhausted.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CheckpointSequence;

    #[test]
    fn advancement_preserves_sequence_across_integer_boundaries() {
        for (current, expected) in [
            (0, 1),
            (255, 256),
            (4_294_967_295, 4_294_967_296),
            (u64::MAX - 1, u64::MAX),
        ] {
            let next = CheckpointSequence::new(current).checked_next().unwrap();

            assert_eq!(next.value(), expected);
        }
    }

    #[test]
    fn advancement_rejects_an_exhausted_counter() {
        assert_eq!(CheckpointSequence::new(u64::MAX).checked_next(), None);
    }
}
