//! Errors from validating typed recipient descriptors.

use houseki_crypto::{CryptoSuiteError, MlKem1024EncapsulationKeyError};
use houseki_types::{AddressFormatVersion, NetworkId};
use thiserror::Error;

/// A failure to validate a recipient's declared context or public key encoding.
#[derive(Debug, Error)]
pub enum NoteRecipientError {
    /// The declared network differs from the caller's intended network.
    #[error("recipient descriptor belongs to a different network")]
    NetworkMismatch {
        /// Complete network identifier declared by the descriptor.
        actual: NetworkId,
    },

    /// The complete address format identifier has no supported recipient rules.
    #[error("unsupported recipient address format {}", .version.value())]
    UnsupportedAddressFormat {
        /// Complete address format version supplied in the descriptor.
        version: AddressFormatVersion,
    },

    /// The descriptor names an unsupported cryptographic suite.
    #[error(transparent)]
    UnsupportedSuite(
        /// Original resolution failure retaining the complete suite identifier.
        #[from]
        CryptoSuiteError,
    ),

    /// The supplied ML-KEM-1024 public key encoding is not canonical.
    #[error(transparent)]
    InvalidEncapsulationKey(
        /// Original public key validation failure.
        #[from]
        MlKem1024EncapsulationKeyError,
    ),
}
