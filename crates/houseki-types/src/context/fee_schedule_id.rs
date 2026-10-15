//! Identifiers for transaction fee schedules.

/// Identifies the fee schedule expected by a transaction or execution context.
///
/// The schedule determines the required fee from the transaction's public
/// workload. Its identifier is separate from the protocol version and carries
/// neither the pricing rules nor the resulting fee amount.
///
/// Every `u32` value is representable, including zero, but constructing an
/// identifier does not establish that the schedule exists or is active.
/// Execution must check it against the schedule selected for the current
/// checkpoint and verify the transaction's fee under that schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FeeScheduleId(u32);

impl FeeScheduleId {
    /// Constructs a fee schedule identifier without checking its availability.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric fee schedule identifier.
    pub const fn value(&self) -> u32 {
        self.0
    }
}
