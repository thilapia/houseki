//! Single attempt proving with protected allocation ownership through canonical encoding.

mod request;

pub(crate) use request::Request;

use super::{
    BackendError, codec,
    config::{self, Config},
    random,
    trace::Trace,
};
#[cfg(test)]
use crate::profile::ExpectedIdentity;
use crate::{
    CancellationToken,
    cancellation::Attempt,
    memory::{self, MemoryError, Scope},
    profile::MAX_PROOF_BYTES,
    runtime::Admission,
};
use houseki_types::EncodedTransactionProof;
use p3_air::{Air, DebugConstraintBuilder};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::QuotientAir;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Produces only public canonical bytes after every private backend allocation is released.
///
/// The guarded input remains owned through every return path and its backend copy is allocated
/// only after the process allocator and serial execution mode have passed preflight.
pub(crate) fn prove_encoded<A>(
    admission: &Admission<'_>,
    request: Request<'_, A>,
    trace: Trace,
    token: &CancellationToken,
) -> Result<EncodedTransactionProof, BackendError>
where
    A: QuotientAir<Config> + for<'a> Air<DebugConstraintBuilder<'a, Goldilocks>>,
{
    let attempt = Attempt::new(token).ok_or(BackendError::Cancelled)?;

    prove_prepared(admission, request, || Ok(trace), attempt)
}

/// Builds the guarded trace only after the caller attempt owns protected backend allocation.
pub(crate) fn prove_prepared<A>(
    _admission: &Admission<'_>,
    request: Request<'_, A>,
    prepare: impl FnOnce() -> Result<Trace, BackendError>,
    attempt: Attempt<'_>,
) -> Result<EncodedTransactionProof, BackendError>
where
    A: QuotientAir<Config> + for<'a> Air<DebugConstraintBuilder<'a, Goldilocks>>,
{
    let token = attempt.token();
    // Subscriber setup occurs outside private allocation accounting and no application subscriber
    // receives backend events while this attempt owns witnesses.
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        let scope = Scope::from_attempt(attempt).map_err(memory_error)?;

        let result = catch_unwind(AssertUnwindSafe(move || {
            memory::checkpoint();
            let trace = prepare()?;
            if trace.width() != request.air.width()
                || request.public.len() != request.air.num_public_values()
                || !trace.height().is_power_of_two()
                || trace.height() < 512
                || trace.height().ilog2() as usize != request.layout.log_rows
                || trace.width() != request.layout.width
            {
                return Err(BackendError::InvalidTrace);
            }

            let config = config::assemble(request.prefix, random::fresh_generators()?);

            let matrix = RowMajorMatrix::new(trace.values().to_vec(), trace.width());
            let proof = p3_uni_stark::prove(&config, request.air, matrix, request.public)
                .map_err(|_| BackendError::ProvingFailed)?;

            memory::checkpoint();
            let encoded = codec::encode(request.identity, request.layout, &proof)
                .map_err(BackendError::from)?;

            let public = memory::public_copy(encoded.as_bytes()).map_err(memory_error)?;
            memory::checkpoint();

            EncodedTransactionProof::new(public, MAX_PROOF_BYTES)
                .map_err(|_| BackendError::ProofTooLarge)
        }));

        let result = match result {
            Ok(result) => result,
            Err(payload) => {
                let cancelled = payload.is::<memory::Cancelled>();
                drop(payload);

                Err(if cancelled {
                    BackendError::Cancelled
                } else {
                    BackendError::ProvingFailed
                })
            }
        };

        scope.finish().map_err(memory_error)?;
        if token.is_cancelled() {
            return Err(BackendError::Cancelled);
        }

        result
    })
}

/// Maps allocator and lifecycle failures to fixed backend diagnostics.
fn memory_error(error: MemoryError) -> BackendError {
    match error {
        MemoryError::Cancelled => BackendError::Cancelled,
        MemoryError::AllocationFailed => BackendError::AllocationFailed,
        _ => BackendError::BackendUnavailable,
    }
}

/// Runs the protected path for the internal synthetic test relation and decodes only public bytes.
#[cfg(test)]
pub(crate) fn prove<A>(
    admission: &Admission<'_>,
    prefix: &[u8],
    air: &A,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<config::BackendProof, BackendError>
where
    A: QuotientAir<Config> + for<'a> Air<DebugConstraintBuilder<'a, Goldilocks>>,
{
    let identity = test_identity();
    let layout = test_layout();

    let encoded = prove_encoded(
        admission,
        Request {
            prefix,
            air,
            public,
            identity: &identity,
            layout,
        },
        trace,
        &CancellationToken::new(),
    )?;

    codec::decode(&identity, layout, encoded.as_bytes()).map_err(|_| BackendError::ProvingFailed)
}

/// Synthetic identity shared by protected execution tests without admitting a product profile.
#[cfg(test)]
pub(crate) fn test_identity() -> ExpectedIdentity {
    ExpectedIdentity {
        profile: houseki_types::ProofProfileId::new(0xffff0004),
        relation: crate::profile::Relation::Payment,
        shape: 0x0101,
        manifest: [0x53; 64],
    }
}

/// Exact quotient and trace geometry of the internal square AIR.
#[cfg(test)]
pub(crate) fn test_layout() -> codec::Layout {
    codec::Layout {
        log_rows: 9,
        width: 1,
        quotient_chunks: 4,
        main_next: true,
    }
}

/// Complete attempt interruption with real backend allocations.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProofRuntime,
        backend::square_air::{SquareAir, trace},
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_util::prover_runtime::Phase;

    /// Witness preparation runs inside protection and errors release the account and runtime slot.
    #[test]
    fn prepared_witness_is_protected_and_failure_releases_allocations() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let token = CancellationToken::new();
        let identity = test_identity();
        let public = [Goldilocks::from_u64(289)];
        let result = prove_prepared(
            &lease,
            Request {
                prefix: b"prepared witness",
                air: &SquareAir,
                public: &public,
                identity: &identity,
                layout: test_layout(),
            },
            || {
                assert!(matches!(
                    Scope::enter(&CancellationToken::new()),
                    Err(MemoryError::NestedAttempt)
                ));
                let _trace = trace();

                Err(BackendError::InvalidTrace)
            },
            Attempt::new(&token).unwrap(),
        );

        assert!(matches!(result, Err(BackendError::InvalidTrace)));
        assert!(memory::LAST_USAGE.with(|usage| usage.take()).is_some());
        assert!(Attempt::new(&token).is_none());
        drop(lease);

        assert!(runtime.acquire().is_ok());
    }

    /// Cancels during every long phase, verifies complete release, and rejects token reuse.
    #[test]
    fn cancelled_job_cannot_reuse_private_state() {
        for phase in [
            Phase::Random,
            Phase::Transform,
            Phase::Commitment,
            Phase::Constraint,
            Phase::Opening,
            Phase::Fold,
        ] {
            let runtime = ProofRuntime::new();
            let lease = runtime.acquire().unwrap();
            let identity = test_identity();
            let public = [Goldilocks::from_u64(289)];
            let request = || Request {
                prefix: b"houseki/test/cancellation/v1",
                air: &SquareAir,
                public: &public,
                identity: &identity,
                layout: test_layout(),
            };

            let token = CancellationToken::new();

            memory::interrupt_at(phase, 8, false);
            let result = prove_encoded(&lease, request(), trace(), &token);

            assert!(
                matches!(result, Err(BackendError::Cancelled)),
                "{phase:?}: {result:?}"
            );

            let elapsed = memory::INTERRUPTED_AT.with(|time| time.take().unwrap().elapsed());
            let usage = memory::LAST_USAGE.with(|usage| usage.take().unwrap());

            assert!(usage.0 > 4096 && usage.1 >= usage.0);
            eprintln!(
                "cancel phase={phase:?} cleanup_us={} peak_bytes={} wiped_bytes={}",
                elapsed.as_micros(),
                usage.0,
                usage.1
            );

            assert!(matches!(
                prove_encoded(&lease, request(), trace(), &token),
                Err(BackendError::Cancelled)
            ));
        }

        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();

        let proof = prove(
            &lease,
            b"fresh retry",
            &SquareAir,
            trace(),
            &[Goldilocks::from_u64(289)],
        )
        .unwrap();

        crate::backend::verifier::verify(
            &lease,
            b"fresh retry",
            &SquareAir,
            &proof,
            &[Goldilocks::from_u64(289)],
        )
        .unwrap();
    }

    /// Verifies in an isolated process that expected debug constraint failures bypass panic hooks.
    #[cfg(debug_assertions)]
    #[test]
    fn private_constraint_failures_do_not_reach_panic_hooks() {
        if std::env::var_os("HOUSEKI_PROOFS_PANIC_PROBE").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::prover::tests::private_constraint_failures_do_not_reach_panic_hooks",
                ])
                .env("HOUSEKI_PROOFS_PANIC_PROBE", "1")
                .status()
                .unwrap();

            assert!(status.success());

            return;
        }

        // The child executes this test alone, so replacing its hook cannot affect another test.
        std::panic::set_hook(Box::new(|_| std::process::exit(71)));
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();

        assert!(matches!(
            prove(
                &lease,
                b"invalid private fixture",
                &SquareAir,
                trace(),
                &[Goldilocks::from_u64(290)]
            ),
            Err(BackendError::ProvingFailed)
        ));
        assert!(memory::LAST_USAGE.with(|usage| usage.take()).is_some());
    }

    /// Discards an unexpected unwind payload and all backend storage before returning a fixed error.
    #[test]
    fn backend_unwinding_releases_private_state() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();

        memory::interrupt_at(Phase::Opening, 8, true);

        assert!(matches!(
            prove(
                &lease,
                b"failure",
                &SquareAir,
                trace(),
                &[Goldilocks::from_u64(289)]
            ),
            Err(BackendError::ProvingFailed)
        ));
        assert!(memory::LAST_USAGE.with(|usage| usage.take()).is_some());
    }
}
