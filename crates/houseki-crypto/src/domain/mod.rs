//! Fixed Houseki domains and reusable streaming transcript framing.

mod error;
mod framing;

pub use error::CryptoFramingError;
pub(crate) use framing::Frame;

/// Only registered roles can select a cryptographic domain.
#[derive(Clone, Copy)]
pub(crate) enum Domain {
    NoteEncryptionCore,
    RecipientKemKey,
}

impl Domain {
    fn label(&self) -> &'static [u8] {
        match self {
            Self::NoteEncryptionCore => b"houseki/v1/note/encryption-core",
            Self::RecipientKemKey => b"houseki/v1/recipient/kem-key",
        }
    }
}
