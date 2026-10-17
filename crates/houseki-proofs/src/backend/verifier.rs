//! Verification constructed without private state or an entropy source.

use p3_air::{Air, symbolic::SymbolicAirBuilder};
use p3_goldilocks::Goldilocks;
use p3_uni_stark::VerifierConstraintFolder;

use super::{
    BackendError,
    config::{self, BackendProof, Config},
    random::BackendRng,
};
use crate::runtime::Admission;

/// Checks a decoded proof with a new challenger and generators that cannot emit bytes.
///
/// Callers validate trusted dimensions and canonical encoding before this boundary.
pub(crate) fn verify<A>(
    _admission: &Admission<'_>,
    prefix: &[u8],
    air: &A,
    proof: &BackendProof,
    public: &[Goldilocks],
) -> Result<(), BackendError>
where
    A: Air<SymbolicAirBuilder<Goldilocks>> + for<'a> Air<VerifierConstraintFolder<'a, Config>>,
{
    if public.len() != air.num_public_values() {
        return Err(BackendError::InvalidProof);
    }

    let config = config::assemble(prefix, std::array::from_fn(|_| BackendRng::verification()));

    p3_uni_stark::verify(&config, air, proof, public).map_err(|_| BackendError::InvalidProof)
}
