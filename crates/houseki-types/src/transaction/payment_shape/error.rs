//! Errors when constructing a [`PaymentShape`](super::PaymentShape).

use thiserror::Error;

/// Errors when constructing a [`PaymentShape`](super::PaymentShape).
#[derive(Debug, Error)]
pub enum PaymentShapeError {
    /// A payment must spend at least one real input.
    #[error("a payment must have at least one real input")]
    EmptyInputs,

    /// A payment must create at least one ordinary note output.
    #[error("a payment must have at least one ordinary note output")]
    EmptyOutputs,
}
