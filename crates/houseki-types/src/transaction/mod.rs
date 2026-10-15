//! Shared values for transaction bodies and envelopes.

mod kind;
mod payment_count_limits;
mod payment_shape;

pub use kind::TransactionKind;
pub use payment_count_limits::{PaymentCountLimits, PaymentCountLimitsError};
pub use payment_shape::{PaymentShape, PaymentShapeError};
