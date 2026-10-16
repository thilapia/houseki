use houseki_types::PaymentCountLimitsError;
use thiserror::Error;

/// A failure to construct typed payment inputs for note encryption.
#[derive(Debug, Error)]
pub enum PaymentEncryptionCoreError {
    /// The core has no ordinary note outputs.
    #[error("a payment encryption core must have at least one note output")]
    EmptyOutputs,

    /// An actual input or output count exceeds its supplied maximum.
    #[error(transparent)]
    CountLimitExceeded(#[from] PaymentCountLimitsError),
}
