//! Complete preflighted public transaction delta without a public application constructor.

use crate::EffectRecord;

/// A complete accepted transition built only by the ordered evaluator.
pub(crate) struct TransactionDelta {
    /// Origin, ordered markers/appends and coalesced before/after account and pool
    /// values.
    pub(crate) effect: EffectRecord,
}
