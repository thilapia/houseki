use thiserror::Error;

/// Errors when constructing [`PaymentInputs`](super::PaymentInputs).
#[derive(Debug, Error)]
pub enum PaymentInputsError {
    /// The payment has no input nullifiers.
    #[error("a payment must have at least one input nullifier")]
    EmptyInputs,

    /// The input list exceeds the supplied inclusive maximum.
    #[error("payment input count {actual} exceeds the maximum of {maximum}")]
    InputCountExceedsLimit {
        /// The number of supplied input nullifiers.
        actual: usize,
        /// The supplied inclusive maximum input count.
        maximum: usize,
    },

    /// Two input slots contain the same nullifier.
    #[error("input nullifier at index {duplicate_index} repeats index {first_index}")]
    DuplicateNullifier {
        /// The zero based index of the first occurrence.
        first_index: usize,
        /// The zero based index of the first repeated occurrence.
        duplicate_index: usize,
    },
}
