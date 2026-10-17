//! Failures while projecting completed bodies or encrypting checked note outputs.

use houseki_crypto::{
    CryptoFramingError, NoteEncryptionContextError, NoteEncryptionError, NotePayloadError,
    PaymentEncryptionCoreError, RewardWithdrawalEncryptionCoreError,
};
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

    /// The reward withdrawal fields cannot form a typed encryption core.
    #[error(transparent)]
    WithdrawalCore(
        /// Original failure from assembling the withdrawal core.
        #[from]
        RewardWithdrawalEncryptionCoreError,
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

/// A failure to match and encrypt an opening for a selected transaction output.
///
/// Diagnostics contain no private amount, blinding, plaintext or secret key material.
#[derive(Debug, Error)]
pub enum NoteOutputEncryptionError {
    /// The output index or complete core cannot form an encryption context.
    #[error("could not prepare note output encryption context: {0}")]
    Context(
        /// Original selection or core framing failure retaining public metadata.
        #[from]
        NoteEncryptionContextError,
    ),

    /// The expected recipient belongs to a different network than the transaction core.
    #[error("note recipient network does not match the transaction")]
    NetworkMismatch,

    /// The opening's retained recipient differs from the complete expected snapshot.
    #[error("note opening does not match the expected recipient")]
    RecipientMismatch,

    /// The opening does not derive the commitment selected from the transaction core.
    #[error("note opening does not match the selected output commitment")]
    CommitmentMismatch,

    /// The matched opening contains a different amount than the public withdrawal amount.
    #[error("note opening amount does not match the public withdrawal amount")]
    WithdrawalAmountMismatch,

    /// Recipient binding or commitment framing failed without returning a digest.
    #[error("could not derive note output commitment: {0}")]
    CommitmentFraming(
        /// Original framing failure without private opening material.
        #[from]
        CryptoFramingError,
    ),

    /// Complete suite sealing failed without returning a partial output.
    #[error("could not encrypt note output: {0}")]
    Encryption(
        /// Original bounded sealing failure from crypto.
        #[from]
        NoteEncryptionError,
    ),
}
