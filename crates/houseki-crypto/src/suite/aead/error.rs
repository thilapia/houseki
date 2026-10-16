use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub(in crate::suite) enum NoteAeadError {
    #[error("plaintext length {actual} exceeds limit {maximum}")]
    PlaintextTooLong { actual: usize, maximum: usize },
    #[error("AEAD length exceeds an algorithm or host limit")]
    LengthLimitExceeded,
    #[error("note encryption failed")]
    EncryptionFailed,
    #[error("note authentication failed")]
    AuthenticationFailed,
}
