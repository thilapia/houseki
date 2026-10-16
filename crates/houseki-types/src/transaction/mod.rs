//! Shared values for transaction bodies and envelopes.

mod context;
mod encoded_transaction_proof;
mod kind;
mod payment;
mod payment_count_limits;
mod payment_envelope;
mod payment_inputs;
mod payment_outputs;
mod payment_shape;

pub use context::TransactionContext;
pub use encoded_transaction_proof::{EncodedTransactionProof, EncodedTransactionProofError};
pub use kind::TransactionKind;
pub use payment::PaymentBody;
pub use payment_count_limits::{PaymentCountLimits, PaymentCountLimitsError};
pub use payment_envelope::PaymentEnvelope;
pub use payment_inputs::{PaymentInputs, PaymentInputsError};
pub use payment_outputs::{PaymentOutputs, PaymentOutputsError};
pub use payment_shape::{PaymentShape, PaymentShapeError};
