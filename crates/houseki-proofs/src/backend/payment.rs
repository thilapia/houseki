//! Concrete complete-payment adapters over the protected proving and bounded verification path.

#[cfg(feature = "prover")]
use super::{
    BackendError, Trace,
    prover::{self, Request},
};
use super::{VerificationError, codec, verifier};
#[cfg(feature = "prover")]
use crate::cancellation::Attempt;
use crate::{
    circuits::payment::PaymentAir, profile::ExpectedIdentity, runtime::Admission,
    statement::Statement,
};
use houseki_types::EncodedTransactionProof;

/// Verifies only under geometry selected independently from trusted public counts.
pub(crate) fn verify_payment(
    admission: &Admission<'_>,
    statement: &Statement,
    identity: &ExpectedIdentity,
    air: &PaymentAir<'_>,
    proof: &EncodedTransactionProof,
) -> Result<(), VerificationError> {
    let decoded = codec::decode(identity, air.layout.codec(), proof.as_bytes())
        .map_err(VerificationError::Encoding)?;
    verifier::verify(
        admission,
        &statement.prefix,
        air,
        &decoded,
        &statement.public_values,
    )
    .map_err(|_| VerificationError::InvalidProof)
}

/// Constructs and proves the entire transaction under one protected allocation scope and attempt.
#[cfg(feature = "prover")]
pub(crate) fn prove_payment(
    admission: &Admission<'_>,
    statement: &Statement,
    identity: &ExpectedIdentity,
    air: &PaymentAir<'_>,
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
            layout: air.layout.codec(),
        },
        prepare,
        attempt,
    )
}
