//! One ordinary output containing exactly the withdrawal body's positive public amount.

mod air;
mod evidence;
#[cfg(all(test, feature = "prover"))]
mod fixture;
#[cfg(feature = "prover")]
mod prover;
#[cfg(feature = "prover")]
mod trace;
mod verifier;

pub(crate) use air::WithdrawalAir;
pub use evidence::VerifiedRewardWithdrawal;
#[cfg(feature = "prover")]
pub use prover::prove_reward_withdrawal;
pub use verifier::verify_reward_withdrawal;

/// Actual family proofs and adversarial public inputs through the exported facade.
#[cfg(all(test, feature = "prover", feature = "experimental-profiles"))]
mod tests {
    use super::*;
    use crate::{
        CancellationToken, ProofContext, ProofEncodingError, ProofRuntime, ProveError, VerifyError,
    };
    use houseki_types::{EncodedTransactionProof, RewardWithdrawalBody};
    use std::time::Instant;

    /// A fresh verifier binds every body field after the original witness and prover runtime expire.
    #[test]
    fn withdrawal_proof_round_trip_binds_complete_body() {
        let (opening, body) = fixture::withdrawal((1_u128 << 64) + 3, 3);
        let context = ProofContext::new(body.context()).unwrap();
        let start = Instant::now();
        let proof = {
            let runtime = ProofRuntime::new();
            prove_reward_withdrawal(
                &runtime,
                &body,
                &opening,
                &context,
                &CancellationToken::new(),
            )
            .unwrap()
        };
        let proving = start.elapsed();
        drop(opening);

        let verifier = ProofRuntime::new();
        let start = Instant::now();
        let evidence = verify_reward_withdrawal(&verifier, &body, &proof, &context).unwrap();
        println!(
            "withdrawal family: bytes={} prove_ms={} verify_ms={}",
            proof.byte_len(),
            proving.as_millis(),
            start.elapsed().as_millis()
        );
        assert!(std::ptr::eq(evidence.body(), &body));
        assert!(std::ptr::eq(evidence.context(), &context));
        assert!(verifier.acquire().is_ok());

        let bytes = body.to_bytes(context.body_limits()).unwrap();
        for offset in [
            8, 71, 72, 76, 80, 84, 92, 100, 163, 164, 2755, 2756, 2763, 2764, 2772, 2780, 2796,
            2859, 2860, 4427, 4436, 4438,
        ] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            let changed =
                RewardWithdrawalBody::from_bytes(&changed, context.body_limits()).unwrap();
            assert!(
                verify_reward_withdrawal(&verifier, &changed, &proof, &context).is_err(),
                "body byte {offset}"
            );
            if changed.context() != body.context()
                && let Ok(changed_context) = ProofContext::new(changed.context())
            {
                assert!(
                    verify_reward_withdrawal(&verifier, &changed, &proof, &changed_context)
                        .is_err(),
                    "matching context at byte {offset}"
                );
            }
        }

        for offset in [8, 12, 16, 20, 24, 87] {
            let mut changed = proof.as_bytes().to_vec();
            changed[offset] ^= 1;
            let changed = EncodedTransactionProof::new(changed, context.max_proof_bytes()).unwrap();
            assert!(
                matches!(
                    verify_reward_withdrawal(&verifier, &body, &changed, &context),
                    Err(VerifyError::Encoding(_))
                ),
                "header byte {offset}"
            );
        }

        let empty = EncodedTransactionProof::new(Vec::new(), context.max_proof_bytes()).unwrap();
        assert!(matches!(
            verify_reward_withdrawal(&verifier, &body, &empty, &context),
            Err(VerifyError::Encoding(ProofEncodingError::Truncated))
        ));
    }

    /// Busy and cancellation precede malformed statements, and failed witnesses consume their token.
    #[test]
    fn reward_withdrawal_facade_preserves_error_precedence_and_token_lifetime() {
        let (opening, body) = fixture::withdrawal(1, 0);
        let (other, _) = fixture::withdrawal(2, 0);
        let context = ProofContext::new(body.context()).unwrap();
        let runtime = ProofRuntime::new();
        let token = CancellationToken::new();
        let lease = runtime.acquire().unwrap();
        token.cancel();
        assert!(matches!(
            prove_reward_withdrawal(&runtime, &body, &opening, &context, &token),
            Err(ProveError::Busy)
        ));
        drop(lease);

        assert!(matches!(
            prove_reward_withdrawal(&runtime, &body, &opening, &context, &token),
            Err(ProveError::Cancelled)
        ));
        let token = CancellationToken::new();
        assert!(matches!(
            prove_reward_withdrawal(&runtime, &body, &other, &context, &token),
            Err(ProveError::InvalidWitness)
        ));
        assert!(matches!(
            prove_reward_withdrawal(&runtime, &body, &opening, &context, &token),
            Err(ProveError::Cancelled)
        ));
        assert!(runtime.acquire().is_ok());
    }
}
