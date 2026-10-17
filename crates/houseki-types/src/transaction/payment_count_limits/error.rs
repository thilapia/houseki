//! Errors when constructing or checking [`PaymentCountLimits`](super::PaymentCountLimits).

use thiserror::Error;

/// Errors when constructing or checking [`PaymentCountLimits`](super::PaymentCountLimits).
#[derive(Debug, Error)]
pub enum PaymentCountLimitsError {
    /// The input maximum cannot admit any payment.
    #[error("the payment input limit must be at least one")]
    ZeroInputLimit,

    /// The ordinary note output maximum cannot admit any payment.
    #[error("the payment note output limit must be at least one")]
    ZeroOutputLimit,

    /// The shape has more inputs than the configured maximum.
    #[error("payment input count {actual} exceeds the limit of {maximum}")]
    InputCountExceedsLimit {
        /// The input count in the shape.
        actual: usize,

        /// The inclusive input maximum.
        maximum: usize,
    },

    /// The shape has more ordinary note outputs than the configured maximum.
    #[error("payment note output count {actual} exceeds the limit of {maximum}")]
    OutputCountExceedsLimit {
        /// The ordinary note output count in the shape.
        actual: usize,

        /// The inclusive ordinary note output maximum.
        maximum: usize,
    },
}
