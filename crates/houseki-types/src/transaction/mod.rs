//! Shared values for transaction bodies and envelopes.

mod context;
mod kind;
mod payment_count_limits;
mod payment_inputs;
mod payment_shape;

pub use context::TransactionContext;
pub use kind::TransactionKind;
pub use payment_count_limits::{PaymentCountLimits, PaymentCountLimitsError};
pub use payment_inputs::{PaymentInputs, PaymentInputsError};
pub use payment_shape::{PaymentShape, PaymentShapeError};
