use thiserror::Error;

/// Errors when constructing [`PaymentOutputs`](super::PaymentOutputs).
#[derive(Debug, Error)]
pub enum PaymentOutputsError {
    /// The payment has no ordinary note outputs.
    #[error("a payment must have at least one note output")]
    EmptyOutputs,

    /// The output list exceeds the supplied inclusive maximum.
    #[error("payment note output count {actual} exceeds the maximum of {maximum}")]
    OutputCountExceedsLimit {
        /// The number of supplied ordinary note outputs.
        actual: usize,
        /// The supplied inclusive maximum output count.
        maximum: usize,
    },
}
