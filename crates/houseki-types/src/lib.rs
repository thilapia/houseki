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
//! [`FeeScheduleId`] identifies the fee schedule that execution uses to check
//! the required fee for a transaction's public workload.
//! [`ProofProfileId`] identifies the proof configuration that a verifier must
//! resolve and check against the transaction's expected statement.
//! [`NoteVersion`] identifies a note's format and rules independently of the
//! protocol version used by its creating or spending transaction.
//! [`AddressFormatVersion`] identifies how an address represents its recipient
//! descriptor so that a parser can apply the appropriate format rules.
//! [`CryptoSuiteId`] identifies the complete cryptographic suite that senders
//! and recipients use for note encryption and recovery.
//! [`Epoch`] identifies a validator epoch and provides checked advancement
//! independently of checkpoint progression and committee transition rules.
//! [`WithdrawalNonce`] tracks a reward account's withdrawal counter and provides
//! checked advancement so that execution can reject exhaustion without wrapping.
//! [`TransactionKind`] distinguishes private payments from public reward
//! withdrawals so that each operation can use its own body and validation rules.

mod account;
mod amount;
mod context;
mod transaction;

pub use account::WithdrawalNonce;
pub use amount::{Amount, AmountError};
pub use context::{
    AddressFormatVersion, CheckpointSequence, CryptoSuiteId, Epoch, FeeScheduleId, NoteVersion,
    ProofProfileId, ProtocolVersion, ValidityCheckpointRange, ValidityCheckpointRangeError,
};
pub use transaction::TransactionKind;
