//! Shared values for transaction bodies and envelopes.

mod kind;
mod payment_shape;

pub use kind::TransactionKind;
pub use payment_shape::{PaymentShape, PaymentShapeError};
