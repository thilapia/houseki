//! Private hiding proof execution with separate proving and verification capabilities.

mod codec;
mod config;
#[cfg(any(test, feature = "prover"))]
mod prover;
mod random;
#[cfg(any(test, feature = "prover"))]
mod trace;
mod verifier;
#[cfg(feature = "prover")]
mod witness;

/// Redacted failures from private backend preparation or execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendError {
    /// The operating system could not supply every required private seed.
    EntropyUnavailable,

    /// A bounded storage request could not be allocated.
    AllocationFailed,

    /// Cancellation discarded this attempt or its token had already been consumed.
    Cancelled,

    /// Private allocation protection or complete release accounting was unavailable.
    BackendUnavailable,

    /// Trace dimensions do not match the selected AIR or hiding floor.
    InvalidTrace,

    /// The pinned prover failed without returning a complete proof.
    ProvingFailed,

    /// Cryptographic verification or expected public dimensions failed.
    InvalidProof,
}

/// Real backend behavior under an internal synthetic relation.
#[cfg(test)]
pub(crate) mod tests {
    use super::trace::Trace;
    use super::*;
    use crate::ProofRuntime;
    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    /// A private square root linked to its public square on every trace row.
    pub(crate) struct SquareAir;

    impl<F> BaseAir<F> for SquareAir {
        /// Stores one private root per row.
        fn width(&self) -> usize {
            1
        }

        /// Exposes exactly the expected square.
        fn num_public_values(&self) -> usize {
            1
        }

        /// Bounds the polynomial square and linear continuity constraints.
        fn max_constraint_degree(&self) -> Option<usize> {
            Some(2)
        }
    }

    impl<AB: AirBuilder> Air<AB> for SquareAir {
        /// Constrains the public square and continuity independently of trace preparation.
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let current = main.current_slice()[0];
            let next = main.next_slice()[0];
            let square = builder.public_values()[0];
            builder.assert_eq(current * current, square);
            builder.when_transition().assert_eq(current, next);
        }
    }

    /// Creates the synthetic witness without a public product dispatch route.
    pub(crate) fn trace() -> Trace {
        let mut trace = Trace::new(512, 1, 512).unwrap();
        trace.values_mut().fill(Goldilocks::from_u64(17));
        trace
    }

    /// Verifies real independent randomized proofs and rejects a changed public statement.
    #[test]
    fn fresh_proofs_verify_without_entropy_or_prover_state() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let public = [Goldilocks::from_u64(289)];
        let first = prover::prove(
            &lease,
            b"houseki/test/square/v1",
            &SquareAir,
            trace(),
            &public,
        )
        .unwrap();
        let second = prover::prove(
            &lease,
            b"houseki/test/square/v1",
            &SquareAir,
            trace(),
            &public,
        )
        .unwrap();
        assert_ne!(first.commitments.trace, second.commitments.trace);
        verifier::verify(
            &lease,
            b"houseki/test/square/v1",
            &SquareAir,
            &first,
            &public,
        )
        .unwrap();
        verifier::verify(
            &lease,
            b"houseki/test/square/v1",
            &SquareAir,
            &second,
            &public,
        )
        .unwrap();
        assert!(
            verifier::verify(
                &lease,
                b"houseki/test/square/v1",
                &SquareAir,
                &first,
                &[Goldilocks::from_u64(290)]
            )
            .is_err()
        );
        assert!(
            verifier::verify(
                &lease,
                b"houseki/test/square/v2",
                &SquareAir,
                &first,
                &public
            )
            .is_err()
        );
    }

    /// Runs independent runtimes concurrently without sharing transcript or private commitment state.
    #[test]
    fn independent_proof_requests_use_separate_state() {
        let requests = [289, 289].map(|square| {
            std::thread::spawn(move || {
                let runtime = ProofRuntime::new();
                let lease = runtime.acquire().unwrap();
                prover::prove(
                    &lease,
                    b"houseki/test/concurrent/v1",
                    &SquareAir,
                    trace(),
                    &[Goldilocks::from_u64(square)],
                )
                .unwrap()
            })
        });
        let [first, second] = requests.map(|request| request.join().unwrap());
        assert_ne!(first.commitments.trace, second.commitments.trace);
        let verifier_runtime = ProofRuntime::new();
        let lease = verifier_runtime.acquire().unwrap();
        for proof in [first, second] {
            verifier::verify(
                &lease,
                b"houseki/test/concurrent/v1",
                &SquareAir,
                &proof,
                &[Goldilocks::from_u64(289)],
            )
            .unwrap();
        }
    }

    /// Stops before a backend invocation whenever any per-attempt seed cannot be acquired.
    #[test]
    fn entropy_failure_has_no_deterministic_fallback() {
        for failed_seed in 0..3 {
            let mut calls = 0;
            let result = random::generators_with(|bytes| {
                let fails = calls == failed_seed;
                calls += 1;
                if fails {
                    Err(BackendError::EntropyUnavailable)
                } else {
                    bytes.fill(7);
                    Ok(())
                }
            });
            assert!(matches!(result, Err(BackendError::EntropyUnavailable)));
            assert_eq!(calls, failed_seed + 1);
        }
    }
}
