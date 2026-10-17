//! Native spend equation failures without private witness values.

use houseki_crypto::CryptoFramingError;
use houseki_state::NoteMembershipError;
use thiserror::Error;

/// A failed native spend equation without private values or partial verification evidence.
#[derive(Debug, Error)]
pub enum SpendRelationError {
    /// The opening belongs to a different network than the selected anchor.
    #[error("spend opening network does not match the anchor")]
    NetworkMismatch,

    /// Original spending and nullifier keys do not derive the declared ownership.
    #[error("spend keys do not match the note ownership")]
    OwnershipMismatch,

    /// Actual occupied position and root verification failed.
    #[error("spend membership failed: {0}")]
    Membership(
        /// Original value safe concrete membership failure.
        #[from]
        NoteMembershipError,
    ),

    /// The derived marker differs from the exact declared input nullifier.
    #[error("spend nullifier does not match the declared input")]
    NullifierMismatch,

    /// A fixed ownership, commitment or nullifier transcript could not be framed.
    #[error("could not frame native spend relation: {0}")]
    Framing(
        /// Original safe fixed transcript failure.
        #[from]
        CryptoFramingError,
    ),
}
