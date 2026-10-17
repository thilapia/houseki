//! Native payment relation and exact conservation failures.

use crate::SpendRelationError;
use houseki_crypto::CryptoFramingError;
use houseki_types::PaymentCountLimitsError;
use thiserror::Error;

/// A failed native payment equation without private amounts, keys or membership paths.
#[derive(Debug, Error)]
pub enum PaymentRelationError {
    /// Actual public counts exceed their active maxima.
    #[error("payment count limit failed: {0}")]
    Counts(
        /// Original public count limit failure.
        #[from]
        PaymentCountLimitsError,
    ),

    /// The ordered private input list does not match the complete body input count.
    #[error("payment input witness count mismatch")]
    InputCountMismatch,

    /// The ordered private output list does not match the complete body output count.
    #[error("payment output opening count mismatch")]
    OutputCountMismatch,

    /// The body network or exact anchor root differs from the selected state anchor.
    #[error("payment body does not match the selected note anchor")]
    AnchorMismatch,

    /// Declared input markers repeat within the payment.
    #[error("payment contains a repeated nullifier")]
    DuplicateNullifier,

    /// Bounded duplicate detection storage could not be reserved.
    #[error("could not reserve payment relation storage")]
    AllocationFailed,

    /// An ordered input fails its linked ownership or actual membership equation.
    #[error("payment input {input_index} failed its native spend relation: {source}")]
    Spend {
        /// Zero based public body input slot.
        input_index: usize,

        /// Value safe native spend failure.
        #[source]
        source: SpendRelationError,
    },

    /// A positive output opening belongs to a different network from the body.
    #[error("payment output {output_index} opening belongs to another network")]
    OutputNetworkMismatch {
        /// Zero based public output slot.
        output_index: usize,
    },

    /// An output opening does not derive the exact commitment at its ordered body slot.
    #[error("payment output {output_index} commitment mismatch")]
    OutputCommitmentMismatch {
        /// Zero based public output slot.
        output_index: usize,
    },

    /// A fixed output commitment transcript could not be framed.
    #[error("could not frame payment output commitment: {0}")]
    Framing(
        /// Original safe fixed transcript failure.
        #[from]
        CryptoFramingError,
    ),

    /// Protected exact accumulation could not represent the complete sum.
    #[error("payment amount total overflow")]
    ArithmeticOverflow,

    /// All input amounts do not equal all output amounts plus the separate fee once.
    #[error("payment amount conservation mismatch")]
    ConservationMismatch,
}
