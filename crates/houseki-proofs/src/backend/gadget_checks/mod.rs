//! Shared proof round trips for isolated gadget relations with explicit test identities.

mod amount;
mod encoding;
mod notes;
mod poseidon2;

use super::{
    BackendError, codec,
    config::{BackendProof, Config},
    prover::{self, Request},
    trace::Trace,
};
use crate::{CancellationToken, runtime::Admission};
use p3_air::{Air, DebugConstraintBuilder};
use p3_goldilocks::Goldilocks;
use p3_uni_stark::QuotientAir;

/// Traverses protected proving and bounded decoding under the caller's test geometry.
pub(super) fn prove<A>(
    admission: &Admission<'_>,
    request: Request<'_, A>,
    trace: Trace,
) -> Result<BackendProof, BackendError>
where
    A: QuotientAir<Config> + for<'a> Air<DebugConstraintBuilder<'a, Goldilocks>>,
{
    let identity = request.identity;
    let layout = request.layout;
    let encoded = prover::prove_encoded(admission, request, trace, &CancellationToken::new())?;

    codec::decode(identity, layout, encoded.as_bytes()).map_err(|_| BackendError::InvalidProof)
}
