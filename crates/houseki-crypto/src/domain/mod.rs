//! Fixed Houseki domains and reusable streaming transcript framing.

mod error;
mod framing;

pub use error::CryptoFramingError;
pub(crate) use framing::Frame;

/// Only registered roles can select a cryptographic domain.
#[derive(Clone, Copy)]
pub(crate) enum Domain {
    /// Binds the canonical ledger reference state record under schema 1.
    LedgerReferenceState,

    /// Binds the canonical ledger execution policy record under schema 1.
    LedgerExecutionPolicy,

    /// Binds the canonical ledger ordered occurrences record under schema 1.
    LedgerOrderedOccurrences,

    /// Binds the canonical ledger receipts record under schema 1.
    LedgerReceipts,

    /// Binds the canonical ledger public effects record under schema 1.
    LedgerPublicEffects,

    /// Binds the canonical ledger system events record under schema 1.
    LedgerSystemEvents,

    /// Binds the canonical ledger execution artifact record under schema 1.
    LedgerExecutionArtifact,

    /// Binds the canonical ledger fixture order unit record under schema 1.
    LedgerFixtureOrderUnit,

    /// Binds the canonical ledger fixture order stream record under schema 1.
    LedgerFixtureOrderStream,

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
            Self::LedgerReferenceState => b"houseki/v1/ledger/reference-state",
            Self::LedgerExecutionPolicy => b"houseki/v1/ledger/execution-policy",
            Self::LedgerOrderedOccurrences => b"houseki/v1/ledger/ordered-occurrences",
            Self::LedgerReceipts => b"houseki/v1/ledger/receipts",
            Self::LedgerPublicEffects => b"houseki/v1/ledger/public-effects",
            Self::LedgerSystemEvents => b"houseki/v1/ledger/system-events",
            Self::LedgerExecutionArtifact => b"houseki/v1/ledger/execution-artifact",
            Self::LedgerFixtureOrderUnit => b"houseki/v1/ledger/fixture-order-unit",
            Self::LedgerFixtureOrderStream => b"houseki/v1/ledger/fixture-order-stream",
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
