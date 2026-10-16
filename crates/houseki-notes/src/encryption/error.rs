//! Errors from projecting completed bodies into note encryption inputs.

use houseki_crypto::{NotePayloadError, PaymentEncryptionCoreError};
use thiserror::Error;

/// A failure to derive typed encryption inputs from a completed transaction body.
#[derive(Debug, Error)]
pub enum NoteContextError {
    /// The payment fields cannot form a core under the supplied count limits.
    #[error(transparent)]
    PaymentCore(
        /// Original failure from checking or assembling the payment core.
        #[from]
        PaymentEncryptionCoreError,
    ),

    /// An output payload exceeds its limit or has no recognized complete layout.
    #[error("note output {output_index} has an invalid encryption payload")]
    OutputPayload {
        /// Zero based position of the first invalid payload in body order.
        output_index: usize,

        /// Original bounded payload resolution failure.
        #[source]
        source: NotePayloadError,
    },
}
