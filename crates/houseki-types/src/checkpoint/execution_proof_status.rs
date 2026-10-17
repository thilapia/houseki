//! Reported verification of a checkpoint's execution proof package.

/// A reporter's view of whether a checkpoint's execution claim has been proved.
///
/// Verification covers the ledger proof, every required wallet proof and all required public
/// authorizations.
///
/// The verifier must link them to the same checkpoint statement, including its bodies, ordered
/// occurrences, effects, outcomes, context and state roots, under allowed proof profiles and a
/// trusted starting state.
///
/// Checking the ledger proof alone is insufficient.
///
/// Consensus finality is reported separately by [`super::FinalityStatus`].
///
/// Verification of execution does not establish consensus finality, continued availability of
/// proofs or transaction payloads, or successful note recovery.
///
/// Native execution and wallet proof checks also do not establish this status without the ledger
/// proof.
///
/// This public reporting value carries no verification evidence.
///
/// Constructing or receiving it cannot authorize state changes or replace proof, statement and
/// authorization verification.
///
/// Package formats and wire tags remain separate contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionProofStatus {
    /// The reporter has not verified the checkpoint's execution claim.
    ///
    /// This includes missing or unchecked evidence and does not assert that a valid proof
    /// package cannot exist or that another observer has not verified it.
    Unverified,

    /// The reporter has verified the complete execution proof package against
    /// the checkpoint's expected statement and trusted starting state.
    Verified,
}
