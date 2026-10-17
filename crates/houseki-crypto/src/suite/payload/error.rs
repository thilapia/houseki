//! Errors from bounded note payload inspection before cryptographic recovery.

use crate::CryptoSuiteError;
use thiserror::Error;

/// A failure to resolve a suite from the public layout of a note payload.
#[derive(Debug, Error)]
pub enum NotePayloadError {
    /// The payload exceeds the caller's active inclusive byte limit.
    #[error("note payload length {actual} exceeds the maximum of {maximum} bytes")]
    PayloadLengthExceedsLimit {
        /// Number of supplied payload bytes, excluding the separate KEM encapsulation.
        actual: usize,

        /// Inclusive payload limit supplied by the caller.
        maximum: usize,
    },

    /// The payload lacks a complete identifier or the recognized suite's nonce and tag.
    #[error("note payload length {actual} is below the required minimum of {minimum} bytes")]
    TruncatedPayload {
        /// Number of supplied payload bytes.
        actual: usize,

        /// Bytes required for the header or recognized suite layout being checked.
        minimum: usize,
    },

    /// The complete header names an unsupported suite and cannot select a payload layout.
    #[error(transparent)]
    UnsupportedSuite(
        /// Original resolution failure retaining the complete suite identifier.
        #[from]
        CryptoSuiteError,
    ),
}
