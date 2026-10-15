//! Shared protocol values for Houseki.
//!
//! [`Amount`] stores an exact atom count with [`Amount::ATOMS_PER_COIN`] atoms
//! per coin and an upper bound of [`Amount::MAX_ATOMS`].
//!
//! ```
//! use houseki_types::Amount;
//!
//! let amount = Amount::from_atoms(Amount::ATOMS_PER_COIN)?;
//! assert_eq!(amount.atoms(), 100_000_000_000_000_000_000);
//! # Ok::<(), houseki_types::AmountError>(())
//! ```
//!
//! [`CheckpointSequence`] identifies a numeric checkpoint position and provides
//! checked advancement without wrapping when the counter is exhausted.
//! [`ValidityCheckpointRange`] bounds transaction validity with an inclusive
//! start and end, rejecting bounds that would put the start after the end.
//! [`ProtocolVersion`] identifies protocol rules independently of the versions
//! used for software releases, note formats and proof profiles.

mod amount;
mod context;

pub use amount::{Amount, AmountError};
pub use context::{
    CheckpointSequence, ProtocolVersion, ValidityCheckpointRange, ValidityCheckpointRangeError,
};
