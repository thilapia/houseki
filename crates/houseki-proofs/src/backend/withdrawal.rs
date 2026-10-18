//! Concrete withdrawal adapters keeping backend proof types and generic configuration private.

#[cfg(feature = "prover")]
use super::{
    BackendError, Trace,
    prover::{self, Request},
};
use super::{VerificationError, codec, verifier};
#[cfg(feature = "prover")]
use crate::cancellation::Attempt;
use crate::{
    circuits::reward_withdrawal::WithdrawalAir,
    profile::{ExpectedIdentity, reward_withdrawal::LAYOUT},
    runtime::Admission,
    statement::Statement,
};
use houseki_types::EncodedTransactionProof;

/// Decodes under fixed family dimensions and verifies without returning backend representations.
pub(crate) fn verify_withdrawal(
    admission: &Admission<'_>,
    statement: &Statement,
    identity: &ExpectedIdentity,
    proof: &EncodedTransactionProof,
) -> Result<(), VerificationError> {
    let decoded =
        codec::decode(identity, LAYOUT, proof.as_bytes()).map_err(VerificationError::Encoding)?;
    verifier::verify(
        admission,
        &statement.prefix,
        &WithdrawalAir::new(),
        &decoded,
        &statement.public_values,
    )
    .map_err(|_| VerificationError::InvalidProof)
}

/// Uses the shared protected prover with one statically selected complete withdrawal AIR.
#[cfg(feature = "prover")]
pub(crate) fn prove_withdrawal(
    admission: &Admission<'_>,
    statement: &Statement,
    identity: &ExpectedIdentity,
    air: &WithdrawalAir,
    prepare: impl FnOnce() -> Result<Trace, BackendError>,
    attempt: Attempt<'_>,
) -> Result<EncodedTransactionProof, BackendError> {
    prover::prove_prepared(
        admission,
        Request {
            prefix: &statement.prefix,
            air,
            public: &statement.public_values,
            identity,
            layout: LAYOUT,
        },
        prepare,
        attempt,
    )
}
