//! Errors from selecting and preparing an output context.

use thiserror::Error;

use crate::CryptoFramingError;

/// A failure to prepare one output's note encryption context.
#[derive(Debug, Error)]
pub enum NoteEncryptionContextError {
    /// The supplied zero based index does not select an actual payment output.
    #[error("note output index {index} is outside {output_count} outputs")]
    OutputIndexOutOfBounds {
        /// Complete output index supplied by the caller.
        index: u64,

        /// Number of outputs available in the typed payment core.
        output_count: usize,
    },

    /// The complete typed core could not be framed for digest derivation.
    #[error(transparent)]
    CoreDigest(
        /// Original failure from core transcript framing.
        #[from]
        CryptoFramingError,
    ),
}
