//! Private hiding proof execution with separate proving and verification capabilities.

#[cfg(test)]
mod addition_proof;
#[cfg(test)]
mod amount_proof;
#[cfg(test)]
mod application_hash_proof;
#[cfg(test)]
mod byte_proof;
#[cfg(test)]
mod bytes_proof;
mod codec;
mod config;
mod error;
#[cfg(test)]
mod extraction_proof;
#[cfg(test)]
mod field_proof;
#[cfg(test)]
mod framed_sponge_proof;
#[cfg(test)]
mod framing_block_proof;
#[cfg(test)]
mod framing_proof;
#[cfg(test)]
mod gadget_proof;
mod hash;
#[cfg(test)]
mod inactive_withdrawal_air;
#[cfg(test)]
mod opening_proof;
#[cfg(test)]
mod opening_statement;
#[cfg(test)]
mod permutation_proof;
#[cfg(any(test, feature = "prover"))]
mod prover;
mod random;
#[cfg(test)]
mod recipient_hash_proof;
#[cfg(test)]
mod recipient_pair_proof;
#[cfg(test)]
mod square_air;
#[cfg(any(test, feature = "prover"))]
mod trace;
mod verifier;
mod withdrawal;
#[cfg(feature = "prover")]
mod witness;

pub(crate) use codec::{CodecError, Layout};
pub(crate) use error::{BackendError, VerificationError};
#[cfg(feature = "prover")]
pub(crate) use trace::Trace;
#[cfg(feature = "prover")]
pub(crate) use withdrawal::prove_withdrawal;
pub(crate) use withdrawal::verify_withdrawal;
#[cfg(feature = "prover")]
pub(crate) use witness::OpeningFields;

/// Real backend behavior under an internal synthetic relation.
#[cfg(test)]
mod tests {
    use super::square_air::{SquareAir, trace};
    use super::*;
    use crate::ProofRuntime;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

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

    /// Stops before a backend invocation whenever any per attempt seed cannot be acquired.
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
