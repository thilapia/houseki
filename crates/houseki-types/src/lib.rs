//! Shared protocol values for Houseki.
//!
//! [`Amount`] stores an exact atom count with [`Amount::ATOMS_PER_COIN`] atoms
//! per coin and an upper bound of [`Amount::MAX_ATOMS`].
//!
//! ```
//! use houseki_types::Amount;
//!
//! let amount = Amount::from_atoms(Amount::ATOMS_PER_COIN)?;
//!
//! assert_eq!(amount.atoms(), 100_000_000_000_000_000_000);
//!
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
//! [`OwnershipCommitment`] stores a digest of recipient ownership information,
//! leaving its construction, opening relation and key binding to the profile.
//!
//! [`RecipientDescriptor`] groups address context, an ownership commitment and
//! the full public encapsulation key without validating recipient information.
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
//! [`EncodedMlDsa87PublicKey`] holds the public key bytes for reward withdrawal
//! authority, leaving account binding and signature verification to consumers.
//!
//! [`EncodedMlDsa87Signature`] holds the encoded signature bytes for reward
//! withdrawals, leaving canonical decoding and native verification to consumers.
//!
//! [`RewardAccountId`] stores a Poseidon2 identifier binding the network,
//! signature scheme and withdrawal public key without computing that binding.
//!
//! [`RewardAccount`] groups the declared withdrawal authority, public balance
//! and next nonce, leaving registration and authenticated updates to consumers.
//!
//! [`RewardWithdrawalBody`] groups a declared reward withdrawal with a positive
//! public amount, one ordinary note output and a separate public fee.
//!
//! [`RewardWithdrawalEnvelope`] groups a withdrawal body, encoded output proof
//! and ML-DSA-87 signature without establishing validity or authorization.
//!
//! [`TransactionEnvelope`] carries either complete transaction envelope and
//! derives its operation kind from the selected variant.
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
//! [`PaymentOutputs`] preserves a nonempty ordered list of ordinary note outputs
//! within the supplied output count limit, with the fee kept separate.
//!
//! [`PaymentBody`] assembles the declared payment context, inputs, outputs and
//! public fee, deriving its shape from the lists and rechecking their count limits.
//!
//! [`EncodedTransactionProof`] holds opaque proof bytes within a supplied byte
//! limit, leaving profile decoding and proof verification to consumers.
//!
//! [`PaymentEnvelope`] pairs a payment body with its encoded proof without
//! establishing authorization or eligibility for execution.
//!
//! [`TransactionId`] stores a 64 byte SHA3-512 identifier for the canonical body
//! and kind, derived outside proofs and excluding proof and signature bytes.
//!
//! [`VertexId`] stores a 64 byte SHA3-512 DAG vertex identifier derived outside
//! proofs, leaving vertex encoding and authentication to consensus consumers.
//!
//! [`ValidatorId`] stores a Poseidon2 digest of immutable registration data,
//! preserving validator identity across consensus signing key changes.
//!
//! [`CommitteeId`] stores a Poseidon2 committee snapshot digest to pair with
//! an epoch, leaving snapshot authentication and activation to consumers.
//!
//! [`CommitteeContext`] pairs an epoch with its declared committee snapshot
//! identifier without establishing that the snapshot is authorized for use.
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
//! [`NoteOutput`] pairs a note commitment with its encrypted recovery envelope
//! for use in payment and reward withdrawal bodies.
//!
//! [`ExecutionOutcome`] records acceptance or rejection by the state rules for
//! an eligible occurrence in the canonical execution order.
//!
//! [`Occurrence`] groups a vertex reference, declared author, committee context,
//! payload position and complete envelope without authenticating their binding.
//!
//! [`Receipt`] links a reported execution outcome to a vertex payload position,
//! with checkpoint context and ordering supplied by its containing receipt list.
//!
//! [`ExecutionRejectionReason`] identifies the reported state failure carried
//! by a rejected outcome without assigning wire codes or check precedence.
//!
//! [`CheckpointId`] stores a Poseidon2 checkpoint identifier independently of
//! its sequence number, leaving derivation and authenticated continuity to
//! consumers.
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
mod consensus;
mod context;
mod execution;
mod note;
mod transaction;

pub use account::{
    EncodedMlDsa87PublicKey, EncodedMlDsa87PublicKeyError, EncodedMlDsa87Signature,
    EncodedMlDsa87SignatureError, RewardAccount, RewardAccountId, RewardAccountIdError,
    WithdrawalNonce,
};
pub use address::{
    AddressContext, EncodedMlKem1024PublicKey, EncodedMlKem1024PublicKeyError, OwnershipCommitment,
    OwnershipCommitmentError, RecipientDescriptor,
};
pub use amount::{Amount, AmountError};
pub use checkpoint::{
    AvailabilityStatus, CheckpointId, CheckpointIdError, ExecutionProofStatus, FinalityStatus,
};
pub use consensus::{
    CommitteeContext, CommitteeId, CommitteeIdError, ValidatorId, ValidatorIdError, VertexId,
    VertexIdError,
};
pub use context::{
    AddressFormatVersion, CheckpointSequence, CryptoSuiteId, Epoch, FeeScheduleId, NetworkId,
    NetworkIdError, NoteVersion, ProofProfileId, ProtocolVersion, ValidityCheckpointRange,
    ValidityCheckpointRangeError,
};
pub use execution::{ExecutionOutcome, ExecutionRejectionReason, Occurrence, Receipt};
pub use note::{
    EncodedMlKem1024Ciphertext, EncodedMlKem1024CiphertextError, EncryptedNoteEnvelope,
    EncryptedNoteEnvelopeError, NoteCommitment, NoteCommitmentError, NoteCount, NoteCountError,
    NoteOutput, NotePosition, NoteRoot, NoteRootError, NoteTreeAnchor, Nullifier, NullifierError,
};
pub use transaction::{
    BodyCodecError, BodyCodecLimits, EncodedTransactionProof, EncodedTransactionProofError,
    PaymentBody, PaymentCountLimits, PaymentCountLimitsError, PaymentEnvelope, PaymentInputs,
    PaymentInputsError, PaymentOutputs, PaymentOutputsError, PaymentShape, PaymentShapeError,
    RewardWithdrawalBody, RewardWithdrawalBodyError, RewardWithdrawalEnvelope, TransactionContext,
    TransactionEnvelope, TransactionId, TransactionIdError, TransactionKind,
};
