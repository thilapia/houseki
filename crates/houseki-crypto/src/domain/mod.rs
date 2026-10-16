//! Fixed Houseki domains and reusable streaming transcript framing.

mod error;
mod framing;

pub use error::CryptoFramingError;
pub(crate) use framing::Frame;

/// Only registered roles can select a cryptographic domain.
#[derive(Clone, Copy)]
pub(crate) enum Domain {
    /// Binds a spending secret to its network for ownership commitment composition.
    SpendingKeyCommitment,

    /// Binds a nullifier secret to its network for ownership commitment composition.
    NullifierKeyCommitment,

    /// Binds ordered spending and nullifier key commitments to their network.
    OwnershipCommitment,

    /// Binds a note's owner, recipient, amount and blinding to its network and version.
    NoteCommitment,

    /// Binds a typed transaction core before output encryption.
    NoteEncryptionCore,

    /// Binds a recipient public key to its network and suite.
    RecipientKemKey,

    /// Binds an output context to its encapsulation and nonce.
    NoteAssociatedData,

    /// Separates the network and suite salt used by HKDF extraction.
    NoteKdfExtract,

    /// Separates the associated data used by HKDF expansion.
    NoteKdfExpand,
}

impl Domain {
    /// Returns the exact ASCII label encoded in this domain's transcript.
    fn label(&self) -> &'static [u8] {
        match self {
            Self::SpendingKeyCommitment => b"houseki/v1/ownership/spend-key",
            Self::NullifierKeyCommitment => b"houseki/v1/ownership/nullifier-key",
            Self::OwnershipCommitment => b"houseki/v1/ownership/commitment",
            Self::NoteCommitment => b"houseki/v1/note/commitment",
            Self::NoteEncryptionCore => b"houseki/v1/note/encryption-core",
            Self::RecipientKemKey => b"houseki/v1/recipient/kem-key",
            Self::NoteAssociatedData => b"houseki/v1/note/aad",
            Self::NoteKdfExtract => b"houseki/v1/note/kdf-extract",
            Self::NoteKdfExpand => b"houseki/v1/note/kdf-expand",
        }
    }
}
