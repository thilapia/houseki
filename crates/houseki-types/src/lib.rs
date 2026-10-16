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
//!
//! [`NetworkId`] stores a SHA3-512 genesis commitment that identifies the
//! intended network independently of its protocol and proof versions.
//!
//! [`ValidityCheckpointRange`] bounds transaction validity with an inclusive
//! start and end, rejecting bounds that would put the start after the end.
//!
//! [`ProtocolVersion`] identifies protocol rules independently of the versions
//! used for software releases, note formats and proof profiles.
//!
//! [`FeeScheduleId`] identifies the fee schedule that execution uses to check
//! the required fee for a transaction's public workload.
//!
//! [`ProofProfileId`] identifies the proof configuration that a verifier must
//! resolve and check against the transaction's expected statement.
//!
//! [`NoteVersion`] identifies a note's format and rules independently of the
//! protocol version used by its creating or spending transaction.
//!
//! [`NotePosition`] identifies the original insertion position used to bind a
//! note instance to its nullifier and provides checked numeric advancement.
//!
//! [`NoteCommitment`] stores the 64 byte representation of a Poseidon2 note
//! commitment without computing it or verifying its opening or membership.
//!
//! [`Nullifier`] stores the public spend marker used to reject repeated spending
//! of the same note instance, without deriving it or checking the spent set.
//!
//! [`NoteRoot`] stores a note tree root used by membership proofs without
//! establishing finality or eligibility as a spending anchor.
//!
//! [`AddressFormatVersion`] identifies how an address represents its recipient
//! descriptor so that a parser can apply the appropriate format rules.
//!
//! [`AddressContext`] groups the declared network, address format version and
//! cryptographic suite used to interpret a recipient descriptor.
//!
//! [`CryptoSuiteId`] identifies the complete cryptographic suite that senders
//! and recipients use for note encryption and recovery.
//!
//! [`Epoch`] identifies a validator epoch and provides checked advancement
//! independently of checkpoint progression and committee transition rules.
//!
//! [`WithdrawalNonce`] tracks a reward account's withdrawal counter and provides
//! checked advancement so that execution can reject exhaustion without wrapping.
//!
//! [`TransactionKind`] distinguishes private payments from public reward
//! withdrawals so that each operation can use its own body and validation rules.
//!
//! [`TransactionContext`] groups the declared network, protocol version, proof
//! profile, fee schedule and validity window shared by both transaction bodies.
//!
//! [`PaymentShape`] requires at least one real input and one ordinary note
//! output while keeping the public fee separate from the output count.
//!
//! [`PaymentCountLimits`] checks a payment shape against configurable inclusive
//! maxima for its input and ordinary note output counts.
//!
//! [`PaymentInputs`] pairs a declared note root with a nonempty ordered list of
//! distinct nullifiers checked against the supplied input count limit.
//!
//! [`EncodedMlKem1024PublicKey`] holds the complete public key bytes used by
//! recipient addresses, leaving cryptographic validation to the consumer.
//!
//! [`EncodedMlKem1024Ciphertext`] holds the encapsulation bytes carried by an
//! encrypted note envelope, leaving decapsulation and note recovery to consumers.
//!
//! [`EncryptedNoteEnvelope`] pairs an ML-KEM-1024 encapsulation with an opaque
//! payload checked against a supplied byte limit, leaving its layout to the suite.
//!
//! [`ExecutionOutcome`] records acceptance or rejection by the state rules for
//! an eligible occurrence in the canonical execution order.
//!
//! [`ExecutionRejectionReason`] identifies the reported state failure carried
//! by a rejected outcome without assigning wire codes or check precedence.
//!
//! [`FinalityStatus`] reports checkpoint consensus finality independently of
//! execution proof verification, data availability and note recovery.
//!
//! [`ExecutionProofStatus`] reports verification of a checkpoint's execution
//! proof package, including the required wallet proofs and authorizations.
//!
//! [`AvailabilityStatus`] reports availability of identified data, with separate
//! observations for transaction payloads and execution proof packages.

mod account;
mod address;
mod amount;
mod checkpoint;
mod context;
mod execution;
mod note;
mod transaction;

pub use account::WithdrawalNonce;
pub use address::{AddressContext, EncodedMlKem1024PublicKey, EncodedMlKem1024PublicKeyError};
pub use amount::{Amount, AmountError};
pub use checkpoint::{AvailabilityStatus, ExecutionProofStatus, FinalityStatus};
pub use context::{
    AddressFormatVersion, CheckpointSequence, CryptoSuiteId, Epoch, FeeScheduleId, NetworkId,
    NetworkIdError, NoteVersion, ProofProfileId, ProtocolVersion, ValidityCheckpointRange,
    ValidityCheckpointRangeError,
};
pub use execution::{ExecutionOutcome, ExecutionRejectionReason};
pub use note::{
    EncodedMlKem1024Ciphertext, EncodedMlKem1024CiphertextError, EncryptedNoteEnvelope,
    EncryptedNoteEnvelopeError, NoteCommitment, NoteCommitmentError, NotePosition, NoteRoot,
    NoteRootError, Nullifier, NullifierError,
};
pub use transaction::{
    PaymentCountLimits, PaymentCountLimitsError, PaymentInputs, PaymentInputsError, PaymentShape,
    PaymentShapeError, TransactionContext, TransactionKind,
};
