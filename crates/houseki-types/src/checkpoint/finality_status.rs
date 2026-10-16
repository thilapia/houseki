//! Reported consensus finality for a checkpoint.

/// A reporter's view of whether consensus finality is established for a checkpoint.
///
/// Finality is separate from verification of the complete checkpoint execution
/// proof package and from availability of proofs or transaction payloads. It
/// also does not imply that every transaction occurrence was accepted or that
/// recipients recovered their notes.
///
/// This value reports a status without carrying or verifying its evidence.
/// Consumers must establish finality through the consensus verifier and their
/// trusted starting state before relying on it. Constructing or receiving a
/// status cannot authorize state changes or replace that verification.
/// The consensus algorithm, certificate format and wire tags remain separate
/// contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FinalityStatus {
    /// The reporter has not established consensus finality for the checkpoint.
    /// This includes missing evidence and does not assert that other observers
    /// have not established finality.
    Unconfirmed,

    /// The reporter has established consensus finality for the checkpoint under
    /// its consensus rules and trusted starting state. This does not report
    /// verification of the complete checkpoint execution proof package.
    Finalized,
}
