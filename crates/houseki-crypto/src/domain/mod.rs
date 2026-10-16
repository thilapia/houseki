//! Fixed Houseki domains and reusable streaming transcript framing.

mod error;
mod framing;

pub use error::CryptoFramingError;
pub(crate) use framing::Frame;

/// Only registered roles can select a cryptographic domain.
pub(crate) enum Domain {
    NoteEncryptionCore,
}

impl Domain {
    fn label(&self) -> &'static [u8] {
        match self {
            Self::NoteEncryptionCore => b"houseki/v1/note/encryption-core",
        }
    }
}
