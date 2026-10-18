//! Complete bounded payment composition with profile admission kept separate.

mod air;
mod error;
#[cfg(all(test, feature = "prover"))]
mod fixture;
mod layout;
mod schedule;
#[cfg(feature = "prover")]
mod trace;

pub(crate) use air::PaymentAir;
pub(crate) use error::PaymentLayoutError;
pub(crate) use layout::PaymentLayout;

/// Complete-relation checks before any experimental profile can be admitted.
#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::{
        CancellationToken, PaymentWitness, ProofRuntime, backend,
        profile::{ExpectedIdentity, Relation, payment::SupportedPaymentShape},
        statement::Statement,
    };
    use p3_air::{
        BaseAir, check_all_constraints,
        symbolic::{AirLayout, get_max_constraint_degree},
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    /// Derives all eight exact schedules and checks their actual symbolic degree without traces.
    #[test]
    fn payment_layout_matches_symbolic_air() {
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let shape = SupportedPaymentShape::new(inputs, outputs).unwrap();
                let layout = PaymentLayout::for_shape(shape).unwrap();
                let air = PaymentAir::new(&layout);
                let degree =
                    get_max_constraint_degree(&air, AirLayout::from_air(&air), layout.rows());

                assert_eq!(air.num_public_values(), shape.public_values_len());
                assert_eq!(air.width(), layout.width());
                assert_eq!(degree, 4);
                assert_eq!(
                    layout.rows(),
                    (inputs * 1733 + outputs * 129 + 1).next_power_of_two()
                );
                eprintln!(
                    "shape={inputs}/{outputs} rows={} width={} degree={degree} selectors={} quotient={} main_next={}",
                    layout.rows(),
                    layout.width(),
                    air.num_periodic_columns(),
                    layout.codec().quotient_chunks,
                    air.main_next_row_columns().len()
                );
            }
        }
    }

    /// Checks native equivalence and every composed constraint before running the expensive prover.
    #[test]
    fn payment_one_by_one_trace_and_links() {
        let fixture = fixture::PaymentFixture::new(1, 1);
        let spends = fixture.spends();
        let outputs = fixture.outputs();
        let witness = PaymentWitness::new(&spends, &outputs).unwrap();
        let limits = crate::profile::payment::body_limits();
        houseki_notes::check_payment(
            &fixture.body,
            &fixture.anchor,
            &spends,
            &outputs,
            limits.payment_counts(),
        )
        .unwrap();
        let layout = PaymentLayout::for_shape(SupportedPaymentShape::new(1, 1).unwrap()).unwrap();
        let air = PaymentAir::new(&layout);
        let identity = ExpectedIdentity {
            profile: fixture.body.context().proof_profile_id(),
            relation: Relation::Payment,
            shape: layout.shape().code(),
            manifest: [0x81; 64],
        };
        let statement = Statement::payment(
            &fixture.body,
            &fixture.anchor,
            fixture.body.context(),
            &identity,
            limits,
        )
        .unwrap();
        let trace = trace::build(&air, &witness, &statement, &CancellationToken::new()).unwrap();
        let mut rows = trace.values().to_vec();
        let report = check_all_constraints(
            &air,
            &RowMajorMatrix::new(rows.clone(), layout.width()),
            &statement.public_values,
            Some(4),
        );

        assert!(report.is_ok(), "{report:?}");
        for (phase, column) in [
            (0, 32),
            (128, 48),
            (216, 112),
            (216, 176),
            (1732, 0),
            (1733, 112),
            (1862, 200),
            (2047, 184),
        ] {
            let offset = phase * layout.width() + column;
            rows[offset] += p3_goldilocks::Goldilocks::ONE;
            let report = check_all_constraints(
                &air,
                &RowMajorMatrix::new(rows.clone(), layout.width()),
                &statement.public_values,
                Some(1),
            );

            assert!(!report.is_ok(), "accepted changed cell {phase}:{column}");
            rows[offset] -= p3_goldilocks::Goldilocks::ONE;
        }
    }

    /// Proves the complete smallest payment with a nonzero fee through the protected canonical codec.
    #[test]
    fn payment_one_by_one_complete_proof() {
        let fixture = fixture::PaymentFixture::new(1, 1);
        let spends = fixture.spends();
        let outputs = fixture.outputs();
        let witness = PaymentWitness::new(&spends, &outputs).unwrap();
        houseki_notes::check_payment(
            &fixture.body,
            &fixture.anchor,
            &spends,
            &outputs,
            crate::profile::payment::body_limits().payment_counts(),
        )
        .unwrap();
        let layout = PaymentLayout::for_shape(SupportedPaymentShape::new(1, 1).unwrap()).unwrap();
        let air = PaymentAir::new(&layout);
        let identity = ExpectedIdentity {
            profile: fixture.body.context().proof_profile_id(),
            relation: Relation::Payment,
            shape: layout.shape().code(),
            manifest: [0x81; 64],
        };
        let statement = Statement::payment(
            &fixture.body,
            &fixture.anchor,
            fixture.body.context(),
            &identity,
            crate::profile::payment::body_limits(),
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let trace = trace::build(&air, &witness, &statement, &cancellation).unwrap();
        let matrix = RowMajorMatrix::new(trace.values().to_vec(), trace.width());

        assert!(check_all_constraints(&air, &matrix, &statement.public_values, Some(4)).is_ok());
        drop(matrix);
        drop(trace);

        let runtime = ProofRuntime::new();
        let admission = runtime.acquire().unwrap();
        let result = backend::prove_payment(
            &admission,
            &statement,
            &identity,
            &air,
            || trace::build(&air, &witness, &statement, &cancellation),
            crate::cancellation::Attempt::new(&cancellation).unwrap(),
        );
        eprintln!(
            "generated canonical proof size={:?}",
            backend::LAST_PROOF_SIZE.with(|size| size.get())
        );
        eprintln!(
            "protected peak and wiped bytes={:?}",
            crate::memory::LAST_USAGE.with(|usage| usage.get())
        );
        eprintln!(
            "checkpoint live bytes [transform, constraint, commitment, opening, fold, random]={:?}",
            crate::memory::PHASE_BYTES.with(|peaks| peaks.get())
        );
        let proof = result.unwrap();
        assert!(backend::verify_payment(&admission, &statement, &identity, &air, &proof).is_ok());
        eprintln!(
            "complete 1/1 canonical proof bytes={}",
            proof.as_bytes().len()
        );
    }
}
