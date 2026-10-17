//! Numeric identifiers for validator epochs.

/// A numeric position in the ordered sequence of validator epochs.
///
/// An epoch identifies the validator context used by consensus and staking.
///
/// It is separate from the checkpoint sequence used for transaction validity and does not
/// prescribe a duration or a number of checkpoints per epoch.
///
/// Constructing or advancing this value does not authorize a committee change.
///
/// Every `u64` value is representable, including zero.
///
/// Advancement is checked so that exhausting the counter cannot wrap back to an earlier epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(
    /// Numeric validator epoch without committee activation evidence.
    u64,
);

impl Epoch {
    /// Constructs an epoch from its numeric value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric epoch.
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Returns the next epoch, or `None` when the counter is exhausted.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Construction, conversion and rejection properties of [`Epoch`].
#[cfg(test)]
mod tests {
    use super::Epoch;

    /// Checks that advancement preserves epoch order across integer boundaries.
    #[test]
    fn advancement_preserves_epoch_order_across_integer_boundaries() {
        for (current, expected) in [
            (0, 1),
            (255, 256),
            (4_294_967_295, 4_294_967_296),
            (u64::MAX - 1, u64::MAX),
        ] {
            let epoch = Epoch::new(current);
            let next = epoch.checked_next().unwrap();

            assert_eq!(next.value(), expected);
            assert!(next > epoch);
        }
    }

    /// Checks that advancement rejects an exhausted epoch counter.
    #[test]
    fn advancement_rejects_an_exhausted_epoch_counter() {
        /// Compile time rejection of advancement beyond the maximum epoch.
        const NEXT: Option<Epoch> = Epoch::new(u64::MAX).checked_next();

        assert_eq!(NEXT, None);
    }
}
