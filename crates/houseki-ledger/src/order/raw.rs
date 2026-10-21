//! Complete unverified canonical source unit bytes.

use std::sync::Arc;

/// Owned input bytes that confer neither ordering trust nor cryptographic eligibility.
#[derive(Debug, Clone)]
pub struct RawOrderUnit {
    /// Complete canonical unit record, including every declared envelope.
    bytes: Arc<[u8]>,
}

impl RawOrderUnit {
    /// Retains supplied bytes without authenticating their representation.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Retains already owned immutable canonical source bytes during replay.
    pub(crate) fn from_shared(bytes: Arc<[u8]>) -> Self {
        Self { bytes }
    }

    /// Transfers complete owned input bytes after successful validation.
    pub(crate) fn into_shared(self) -> Arc<[u8]> {
        self.bytes
    }

    /// Borrows the complete source unit representation.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
