//! Complete payment proving from borrowed original owners.

use super::{PaymentAir, PaymentLayout, trace};
use crate::{
    CancellationToken, PaymentWitness, ProofContext, ProofRuntime, ProveError, StatementError,
    backend, cancellation::Attempt, context::require_context,
    profile::payment::SupportedPaymentShape, statement::Statement,
};
use houseki_types::{EncodedTransactionProof, NoteTreeAnchor, PaymentBody};

/// Proves authority, occupied membership, nullifiers, outputs and exact conservation for one payment.
///
/// The application installs [`crate::ProofAllocator`] and uses serial backend execution with
/// panic unwinding enabled so private allocations are cleared on normal exit and unwinding.
///
/// Original openings, keys and paths remain borrowed for this call and no private state is cached.
///
/// Fee policy, unspentness, anchor eligibility, encrypted delivery and atomic execution remain
/// obligations of the consumer before applying the transaction.
///
/// # Errors
///
/// Checks runtime admission before consuming the cancellation token, then exact context, supported
/// counts, family identity and witness counts before encoding the statement or importing secrets.
///
/// Native witness validation precedes protected preparation and fresh backend entropy.
///
/// Every admitted call consumes its token even on failure and returns only a complete proof.
pub fn prove_payment(
    runtime: &ProofRuntime,
    body: &PaymentBody,
    anchor: &NoteTreeAnchor,
    witness: &PaymentWitness<'_>,
    context: &ProofContext,
    cancellation: &CancellationToken,
) -> Result<EncodedTransactionProof, ProveError> {
    let admission = runtime.acquire().map_err(|_| ProveError::Busy)?;
    let attempt = Attempt::new(cancellation).ok_or(ProveError::Cancelled)?;
    require_context(context.expected(), body.context())
        .map_err(|_| StatementError::ContextMismatch)?;
    let shape =
        SupportedPaymentShape::new(body.inputs().input_count(), body.outputs().output_count())
            .map_err(|_| StatementError::UnsupportedShape)?;
    let identity = context.payment_identity(shape)?;
    if witness.inputs().len() != shape.inputs() || witness.outputs().len() != shape.outputs() {
        return Err(ProveError::WitnessCountMismatch);
    }

    let statement = Statement::payment(
        body,
        anchor,
        context.expected(),
        &identity,
        context.body_limits(),
    )?;
    houseki_notes::check_payment(
        body,
        anchor,
        witness.inputs(),
        witness.outputs(),
        context.body_limits().payment_counts(),
    )
    .map_err(|_| ProveError::InvalidWitness)?;
    let layout = PaymentLayout::for_shape(shape).map_err(|_| ProveError::BackendUnavailable)?;
    let air = PaymentAir::new(&layout);
    backend::prove_payment(
        &admission,
        &statement,
        &identity,
        &air,
        || trace::build(&air, witness, &statement, cancellation),
        attempt,
    )
    .map_err(ProveError::from)
}

/// Public admission, binding and attempt lifetime checks.
#[cfg(all(test, feature = "experimental-profiles"))]
mod tests {
    use crate::circuits::payment::fixture::PaymentFixture;
    use crate::{
        CancellationToken, PaymentWitness, ProofContext, ProofRuntime, ProveError, StatementError,
        prove_payment, verify_payment,
    };

    /// Priority shape evidence borrows the exact immutable public arguments after private owners expire.
    #[test]
    fn payment_facade_binds_priority_body_anchor_and_context() {
        let fixture = PaymentFixture::new(4, 2);
        let context = ProofContext::new(fixture.body.context()).unwrap();
        let proof = {
            let spends = fixture.spends();
            let outputs = fixture.outputs();
            let witness = PaymentWitness::new(&spends, &outputs).unwrap();
            prove_payment(
                &ProofRuntime::new(),
                &fixture.body,
                &fixture.anchor,
                &witness,
                &context,
                &CancellationToken::new(),
            )
            .unwrap()
        };

        let body = fixture.body.clone();
        let anchor = fixture.anchor;
        drop(fixture);
        let runtime = ProofRuntime::new();
        let evidence = verify_payment(&runtime, &body, &anchor, &proof, &context).unwrap();
        assert!(std::ptr::eq(evidence.body(), &body));
        assert!(std::ptr::eq(evidence.anchor(), &anchor));
        assert!(std::ptr::eq(evidence.context(), &context));
        assert!(runtime.acquire().is_ok());
        let bytes = body.to_bytes(context.body_limits()).unwrap();
        for offset in [
            8,
            71,
            72,
            76,
            80,
            84,
            92,
            100,
            163,
            180,
            244,
            308,
            372,
            440,
            504,
            2076,
            2078,
            bytes.len() - 1,
        ] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            if let Ok(changed) =
                houseki_types::PaymentBody::from_bytes(&changed, context.body_limits())
            {
                assert!(
                    verify_payment(&runtime, &changed, &anchor, &proof, &context).is_err(),
                    "body byte {offset}"
                );
                if let Ok(changed_context) = ProofContext::new(changed.context()) {
                    assert!(
                        verify_payment(&runtime, &changed, &anchor, &proof, &changed_context)
                            .is_err()
                    );
                }
            }
        }

        let changed = houseki_types::NoteTreeAnchor::new(
            anchor.network_id(),
            houseki_types::NoteCount::new(anchor.count().value() + 1).unwrap(),
            anchor.root(),
        );
        assert!(verify_payment(&runtime, &body, &changed, &proof, &context).is_err());
    }

    /// Busy admission preserves the token and admitted failures consume it before private conversion.
    #[test]
    fn payment_facade_preflight_has_no_private_allocation() {
        let fixture = PaymentFixture::new(4, 2);
        let context = ProofContext::new(fixture.body.context()).unwrap();
        let runtime = ProofRuntime::new();
        let spends = fixture.spends();
        let outputs = fixture.outputs();
        let witness = PaymentWitness::new(&spends[..1], &outputs).unwrap();
        let token = CancellationToken::new();
        let lease = runtime.acquire().unwrap();
        assert!(matches!(
            prove_payment(
                &runtime,
                &fixture.body,
                &fixture.anchor,
                &witness,
                &context,
                &token
            ),
            Err(ProveError::Busy)
        ));
        drop(lease);

        let (result, calls, _) = crate::test_allocator::measure(|| {
            prove_payment(
                &runtime,
                &fixture.body,
                &fixture.anchor,
                &witness,
                &context,
                &token,
            )
        });

        assert!(matches!(result, Err(ProveError::WitnessCountMismatch)));
        assert_eq!(calls, 0);
        assert!(matches!(
            prove_payment(
                &runtime,
                &fixture.body,
                &fixture.anchor,
                &witness,
                &context,
                &token
            ),
            Err(ProveError::Cancelled)
        ));
        let token = CancellationToken::new();
        token.cancel();
        let (result, calls, _) = crate::test_allocator::measure(|| {
            prove_payment(
                &runtime,
                &fixture.body,
                &fixture.anchor,
                &witness,
                &context,
                &token,
            )
        });

        assert!(matches!(result, Err(ProveError::Cancelled)));
        assert_eq!(calls, 0);
        let expected = fixture.body.context();
        let other_context = ProofContext::new(houseki_types::TransactionContext::new(
            expected.network_id(),
            expected.protocol_version(),
            crate::EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE,
            expected.fee_schedule_id(),
            expected.validity_checkpoint_range(),
        ))
        .unwrap();
        assert!(matches!(
            prove_payment(
                &runtime,
                &fixture.body,
                &fixture.anchor,
                &witness,
                &other_context,
                &CancellationToken::new()
            ),
            Err(ProveError::Statement(
                StatementError::IdentityMismatch | StatementError::ContextMismatch
            ))
        ));
        assert!(runtime.acquire().is_ok());
    }
    /// Unsupported body counts reject without statement allocation or private conversion.
    #[test]
    fn payment_facade_rejects_excessive_counts_without_allocation() {
        use houseki_types::{
            Amount, EncodedTransactionProof, Nullifier, PaymentBody, PaymentCountLimits,
            PaymentInputs, PaymentOutputs,
        };

        let fixture = PaymentFixture::new(1, 1);
        let context = ProofContext::new(fixture.body.context()).unwrap();
        let spends = fixture.spends();
        let outputs = fixture.outputs();
        let witness = PaymentWitness::new(&spends, &outputs).unwrap();
        let runtime = ProofRuntime::new();
        let empty = EncodedTransactionProof::new(Vec::new(), context.max_proof_bytes()).unwrap();
        let limits = PaymentCountLimits::new(5, 3).unwrap();
        for (inputs, outputs) in [(5, 1), (1, 3)] {
            let body = PaymentBody::new(
                fixture.body.context(),
                PaymentInputs::new(
                    fixture.anchor.root(),
                    (0..inputs)
                        .map(|i| Nullifier::from_bytes([i as u8; 64]))
                        .collect(),
                    limits,
                )
                .unwrap(),
                PaymentOutputs::new(
                    vec![fixture.body.outputs().outputs()[0].clone(); outputs],
                    limits,
                )
                .unwrap(),
                Amount::from_atoms(1).unwrap(),
                limits,
            )
            .unwrap();
            let (result, calls, _) = crate::test_allocator::measure(|| {
                prove_payment(
                    &runtime,
                    &body,
                    &fixture.anchor,
                    &witness,
                    &context,
                    &CancellationToken::new(),
                )
            });

            assert!(matches!(
                result,
                Err(ProveError::Statement(StatementError::UnsupportedShape))
            ));
            // The fresh cancellation token owns one public atomic allocation.
            assert_eq!(calls, 1);
            let (result, calls, _) = crate::test_allocator::measure(|| {
                verify_payment(&runtime, &body, &fixture.anchor, &empty, &context)
            });

            assert!(matches!(
                result,
                Err(crate::VerifyError::Statement(
                    StatementError::UnsupportedShape
                ))
            ));
            assert_eq!(calls, 0);
        }
    }
    /// Every input, output and backend boundary releases all protected storage after interruption.
    #[test]
    fn payment_lifecycle_cancellation_and_allocation_failure() {
        use crate::memory::{self, TestPoint};
        use p3_util::prover_runtime::Phase;
        let fixture = PaymentFixture::new(4, 2);
        let context = ProofContext::new(fixture.body.context()).unwrap();
        let spends = fixture.spends();
        let outputs = fixture.outputs();
        let witness = PaymentWitness::new(&spends, &outputs).unwrap();
        let runtime = ProofRuntime::new();
        let mut points = Vec::new();
        for index in 0..4 {
            points.extend([
                TestPoint::InputOpening(index),
                TestPoint::InputAuthority(index),
                TestPoint::InputMembership(index),
                TestPoint::InputAccumulation(index),
            ]);
        }

        for index in 0..2 {
            points.extend([
                TestPoint::OutputOpening(index),
                TestPoint::OutputAccumulation(index),
            ]);
        }

        points.extend([TestPoint::Fee, TestPoint::Encoding]);
        points.extend(
            [
                Phase::Random,
                Phase::Transform,
                Phase::Commitment,
                Phase::Constraint,
                Phase::Opening,
                Phase::Fold,
            ]
            .map(TestPoint::Backend),
        );
        for point in points {
            for allocation_failure in [false, true] {
                let token = CancellationToken::new();
                memory::interrupt_payment_at(point, allocation_failure);
                let result = prove_payment(
                    &runtime,
                    &fixture.body,
                    &fixture.anchor,
                    &witness,
                    &context,
                    &token,
                );
                assert!(
                    if allocation_failure {
                        matches!(result, Err(ProveError::AllocationFailed))
                    } else {
                        matches!(result, Err(ProveError::Cancelled))
                    },
                    "{point:?}: {result:?}"
                );
                let (peak, wiped) = memory::LAST_USAGE.with(|usage| usage.take().unwrap());
                assert!(peak >= 8192 * 1185 * 8 && wiped >= peak);
                assert!(runtime.acquire().is_ok());
                assert!(matches!(
                    prove_payment(
                        &runtime,
                        &fixture.body,
                        &fixture.anchor,
                        &witness,
                        &context,
                        &token
                    ),
                    Err(ProveError::Cancelled)
                ));
                eprintln!(
                    "point={point:?} allocation_failure={allocation_failure} peak={peak} wiped={wiped}"
                );
            }
        }

        let retry = PaymentFixture::new(1, 1);
        let retry_spends = retry.spends();
        let retry_outputs = retry.outputs();
        let retry_witness = PaymentWitness::new(&retry_spends, &retry_outputs).unwrap();
        let first = prove_payment(
            &runtime,
            &retry.body,
            &retry.anchor,
            &retry_witness,
            &context,
            &CancellationToken::new(),
        )
        .unwrap();
        let second = prove_payment(
            &runtime,
            &retry.body,
            &retry.anchor,
            &retry_witness,
            &context,
            &CancellationToken::new(),
        )
        .unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
        let first_evidence =
            verify_payment(&runtime, &retry.body, &retry.anchor, &first, &context).unwrap();
        assert!(std::ptr::eq(first_evidence.body(), &retry.body));
        let second_evidence =
            verify_payment(&runtime, &retry.body, &retry.anchor, &second, &context).unwrap();
        assert!(std::ptr::eq(second_evidence.anchor(), &retry.anchor));
    }
}
