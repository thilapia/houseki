//! Errors from cryptographic suite resolution.

use houseki_types::CryptoSuiteId;
use thiserror::Error;

/// A failure to resolve a Houseki note encryption suite identifier.
#[derive(Debug, Error)]
pub enum CryptoSuiteError {
    /// The identifier does not name a recognized suite.
    #[error("unsupported cryptographic suite {}", .id.value())]
    Unsupported {
        /// The complete identifier supplied by the caller.
        id: CryptoSuiteId,
    },
}
