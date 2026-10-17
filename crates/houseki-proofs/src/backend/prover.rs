//! One-attempt proving with fresh private randomness and no persistent commitment cache.

use p3_air::{Air, DebugConstraintBuilder};
use p3_goldilocks::Goldilocks;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_uni_stark::QuotientAir;

use super::{
    BackendError,
    config::{self, BackendProof, Config},
    random,
};
use crate::runtime::Admission;

/// Proves only while the caller retains the shared operation lease.
///
/// Callers keep that lease through encoding and destroy attempt data before retrying.
pub(crate) fn prove<A>(
    _admission: &Admission<'_>,
    prefix: &[u8],
    air: &A,
    trace: RowMajorMatrix<Goldilocks>,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError>
where
    A: QuotientAir<Config> + for<'a> Air<DebugConstraintBuilder<'a, Goldilocks>>,
{
    if trace.width() != air.width()
        || public.len() != air.num_public_values()
        || !trace.height().is_power_of_two()
        || trace.height() < 512
    {
        return Err(BackendError::InvalidTrace);
    }

    let config = config::assemble(prefix, random::fresh_generators()?);

    p3_uni_stark::prove(&config, air, trace, public).map_err(|_| BackendError::ProvingFailed)
}
