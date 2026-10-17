//! Replay counters for public reward account withdrawals.

/// A withdrawal counter scoped to one public reward account.
///
/// Execution requires a withdrawal's nonce to match the account's stored next nonce and advances
/// the counter only when the complete withdrawal succeeds.
///
/// Constructing this value does not establish that it is current or authorize a withdrawal.
///
/// Every `u64` value is representable, including zero.
///
/// The maximum value marks exhaustion because it has no successor.
///
/// Execution must reject withdrawals from an exhausted account rather than reuse an earlier
/// nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WithdrawalNonce(
    /// Full withdrawal counter, including its exhausted maximum value.
    u64,
);

impl WithdrawalNonce {
    /// Constructs a withdrawal nonce from its numeric value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric withdrawal nonce.
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Returns the next nonce, or `None` when the counter is exhausted.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Construction, conversion and rejection properties of [`WithdrawalNonce`].
#[cfg(test)]
mod tests {
    use super::WithdrawalNonce;

    /// Checks that advancement preserves the counter across integer boundaries.
    #[test]
    fn advancement_preserves_the_counter_across_integer_boundaries() {
        for (current, expected) in [(0, 1), (255, 256), (4_294_967_295, 4_294_967_296)] {
            let next = WithdrawalNonce::new(current).checked_next().unwrap();

            assert_eq!(next.value(), expected);
        }
    }

    /// Checks that final advancement reaches exhaustion without wrapping.
    #[test]
    fn final_advancement_reaches_exhaustion_without_wrapping() {
        /// Compile time successor of the final usable withdrawal counter.
        const NEXT: Option<WithdrawalNonce> = WithdrawalNonce::new(u64::MAX - 1).checked_next();
        let exhausted = NEXT.unwrap();

        assert_eq!(exhausted.value(), u64::MAX);
        assert_eq!(exhausted.checked_next(), None);
    }
}
