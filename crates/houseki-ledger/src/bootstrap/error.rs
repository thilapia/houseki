//! Candidate representation errors precede commitment authentication.

/// A manifest cannot construct a bounded, internally consistent bootstrap candidate.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// Independently expected source stream and exact bootstrap continuation disagree.
    #[error("invalid bootstrap source binding")]
    SourceBinding,

    /// Actual logical state digest differs from the independently expected declaration.
    #[error("bootstrap expected state commitment mismatch")]
    StateCommitment,

    /// Complete canonical representation could not be constructed.
    #[error(transparent)]
    Artifact(
        /// Original artifact failure retained as the source.
        #[from]
        crate::ArtifactError,
    ),

    /// A manifest list or key descriptor exceeds the selected reference capacity.
    #[error("bootstrap capacity exceeded")]
    Capacity,

    /// Generated bootstrap state must not import spent markers.
    #[error("initial spent state must be empty")]
    InitialSpent,

    /// Account list contains a repeated complete identity.
    #[error("duplicate account identity")]
    DuplicateAccount,

    /// Validator list contains a repeated complete identity.
    #[error("duplicate validator identity")]
    DuplicateValidator,

    /// Account identity does not match its network and complete authority.
    #[error("account authority binding mismatch")]
    AccountIdentity,

    /// A committee entry maps to an unregistered account.
    #[error("unknown fee beneficiary")]
    UnknownBeneficiary,

    /// A weight is zero or the full width aggregate overflows.
    #[error("invalid committee weight")]
    CommitteeWeight,

    /// Reconstructed note metadata differs from the independently declared metadata.
    #[error("bootstrap note descriptor mismatch")]
    NoteAnchor,

    /// Canonical history is incomplete or contains inconsistent descriptors.
    #[error("invalid bootstrap anchor history")]
    History,

    /// Pool and account totals differ from the bounded supply.
    #[error("bootstrap supply is not conserved")]
    Conservation,

    /// A bounded collection could not reserve local storage.
    #[error("bootstrap allocation failed")]
    Allocation,

    /// Policy validation failed before state reconstruction.
    #[error(transparent)]
    Policy(
        /// Original policy failure retained as the source.
        #[from]
        crate::PolicyError,
    ),

    /// Fixed account identity hashing failed.
    #[error(transparent)]
    AccountHash(
        /// Original accounthash failure retained as the source.
        #[from]
        houseki_crypto::CryptoFramingError,
    ),

    /// Concrete note tree reconstruction failed.
    #[error(transparent)]
    Tree(
        /// Original tree failure retained as the source.
        #[from]
        houseki_state::NoteTreeError,
    ),
}
