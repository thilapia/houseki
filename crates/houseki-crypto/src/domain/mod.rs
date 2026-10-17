//! Fixed Houseki domains and reusable streaming transcript framing.

mod error;
mod framing;

pub use error::CryptoFramingError;
pub(crate) use framing::Frame;

/// Only registered roles can select a cryptographic domain.
#[derive(Clone, Copy)]
pub(crate) enum Domain {
    /// Separates an empty application note tree leaf from occupied commitments.
    NoteTreeEmpty,

    /// Binds an occupied application leaf to the complete network and commitment.
    NoteTreeLeaf,

    /// Binds an ordered pair of application tree nodes and its exact parent level.
    NoteTreeNode,

    /// Binds the depth 64 application top node and complete occupied count.
    NoteTreeRoot,

    /// Detects transcription changes in one complete binary recipient descriptor.
    AddressChecksum,

    /// Binds the complete withdrawal body and operation kind for direct contextual signing.
    WithdrawalSignatureBody,

    /// Binds the actual complete canonical body and fixed operation tag to transaction identity.
    TransactionIdentity,

    /// Binds a network, fixed withdrawal signature scheme and complete public authority key.
    RewardAccountIdentity,

    /// Binds a spending secret to its network for ownership commitment composition.
    SpendingKeyCommitment,

    /// Binds a nullifier secret to its network for ownership commitment composition.
    NullifierKeyCommitment,

    /// Binds ordered spending and nullifier key commitments to their network.
    OwnershipCommitment,

    /// Binds a note's owner, recipient, amount and blinding to its network and version.
    NoteCommitment,

    /// Binds a note instance to its secret nullifier key and original position.
    NoteNullifier,

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
    pub(crate) fn label(&self) -> &'static [u8] {
        match self {
            Self::NoteTreeEmpty => b"houseki/v1/note-tree/empty",
            Self::NoteTreeLeaf => b"houseki/v1/note-tree/leaf",
            Self::NoteTreeNode => b"houseki/v1/note-tree/node",
            Self::NoteTreeRoot => b"houseki/v1/note-tree/root",
            Self::AddressChecksum => b"houseki/v1/address/checksum",
            Self::WithdrawalSignatureBody => b"houseki/v1/reward-withdrawal/body",
            Self::TransactionIdentity => b"houseki/v1/transaction/id",
            Self::RewardAccountIdentity => b"houseki/v1/reward/account",
            Self::SpendingKeyCommitment => b"houseki/v1/ownership/spend-key",
            Self::NullifierKeyCommitment => b"houseki/v1/ownership/nullifier-key",
            Self::OwnershipCommitment => b"houseki/v1/ownership/commitment",
            Self::NoteCommitment => b"houseki/v1/note/commitment",
            Self::NoteNullifier => b"houseki/v1/note/nullifier",
            Self::NoteEncryptionCore => b"houseki/v1/note/encryption-core",
            Self::RecipientKemKey => b"houseki/v1/recipient/kem-key",
            Self::NoteAssociatedData => b"houseki/v1/note/aad",
            Self::NoteKdfExtract => b"houseki/v1/note/kdf-extract",
            Self::NoteKdfExpand => b"houseki/v1/note/kdf-expand",
        }
    }
}
