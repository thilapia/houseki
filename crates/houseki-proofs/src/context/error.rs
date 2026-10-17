//! Failures to recognize a supported protocol and proof profile pair.

/// Failure to recognize a supported protocol and proof profile pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContextError {
    /// The declared protocol identifier has no supported representation rules.
    #[error("unsupported protocol")]
    UnsupportedProtocol,

    /// The profile identifier has no admitted immutable configuration.
    #[error("unsupported proof profile")]
    UnsupportedProfile,

    /// A recognized profile does not belong to the expected protocol.
    #[error("proof profile does not match protocol")]
    ProfileProtocolMismatch,
}
