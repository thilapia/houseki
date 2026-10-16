//! Errors from resolving immutable note format identifiers.

use houseki_types::NoteVersion;
use thiserror::Error;

/// A failure to recognize the complete version identifier of a note format.
#[derive(Debug, Error)]
pub enum NoteFormatError {
    /// The supplied version has no supported immutable note rules.
    #[error("unsupported note version {}", .version.value())]
    Unsupported {
        /// Complete note version supplied by the caller.
        version: NoteVersion,
    },
}
