//! Complete bounded payment composition with profile admission kept separate.

mod air;
mod error;
mod evidence;
#[cfg(all(test, feature = "prover"))]
mod fixture;
mod layout;
#[cfg(feature = "prover")]
mod prover;
mod schedule;
#[cfg(feature = "prover")]
mod trace;
mod verifier;

pub(crate) use air::PaymentAir;
pub(crate) use error::PaymentLayoutError;
pub use evidence::VerifiedPayment;
pub(crate) use layout::PaymentLayout;
#[cfg(feature = "prover")]
pub use prover::prove_payment;
pub use verifier::verify_payment;

/// Complete-relation checks before any experimental profile can be admitted.
#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::{
        CancellationToken, PaymentWitness, ProofRuntime, backend,
        profile::payment::SupportedPaymentShape, statement::Statement,
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

                let mut next_columns = std::collections::BTreeSet::new();
                let expressions =
                    p3_air::symbolic::get_symbolic_constraints(&air, AirLayout::from_air(&air));
                let mut visited = std::collections::HashSet::new();
                for expression in &expressions {
                    collect_next_columns(expression, &mut next_columns, &mut visited);
                }

                assert_eq!(
                    air.main_next_row_columns(),
                    next_columns.into_iter().collect::<Vec<_>>()
                );
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
        let identity = crate::profile::payment::identity(layout.shape());
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
        proof_round_trip(1, 1);
    }

    /// Proves one complete checked shape and records only public artifacts when explicitly requested.
    fn proof_round_trip(inputs: usize, outputs: usize) {
        let fixture = fixture::PaymentFixture::new(inputs, outputs);
        let spends = fixture.spends();
        let output_openings = fixture.outputs();
        let witness = PaymentWitness::new(&spends, &output_openings).unwrap();
        houseki_notes::check_payment(
            &fixture.body,
            &fixture.anchor,
            &spends,
            &output_openings,
            crate::profile::payment::body_limits().payment_counts(),
        )
        .unwrap();
        let layout =
            PaymentLayout::for_shape(SupportedPaymentShape::new(inputs, outputs).unwrap()).unwrap();
        let air = PaymentAir::new(&layout);
        let identity = crate::profile::payment::identity(layout.shape());
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
        let prepare_time = std::cell::Cell::new(std::time::Duration::ZERO);
        let started = std::time::Instant::now();
        let result = backend::prove_payment(
            &admission,
            &statement,
            &identity,
            &air,
            || {
                let start = std::time::Instant::now();
                let result = trace::build(&air, &witness, &statement, &cancellation);
                prepare_time.set(start.elapsed());
                result
            },
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
        let prove_time = started.elapsed();
        let verify_started = std::time::Instant::now();
        assert!(backend::verify_payment(&admission, &statement, &identity, &air, &proof).is_ok());
        let verify_time = verify_started.elapsed();
        eprintln!(
            "shape={inputs}/{outputs} bytes={} prepare_ms={} prove_and_encode_ms={} verify_ms={}",
            proof.byte_len(),
            prepare_time.get().as_millis(),
            (prove_time - prepare_time.get()).as_millis(),
            verify_time.as_millis()
        );
        if let Some(directory) = std::env::var_os("HOUSEKI_PAYMENT_EVIDENCE_DIR") {
            let directory = std::path::PathBuf::from(directory).join(format!("{inputs}-{outputs}"));
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("proof.bin"), proof.as_bytes()).unwrap();
            std::fs::write(
                directory.join("body.bin"),
                fixture
                    .body
                    .to_bytes(crate::profile::payment::body_limits())
                    .unwrap(),
            )
            .unwrap();
            std::fs::write(
                directory.join("anchor-count.bin"),
                fixture.anchor.count().value().to_le_bytes(),
            )
            .unwrap();
        }
    }

    /// Every supported pair, including three inputs, produces one complete canonical proof.
    #[test]
    fn payment_all_supported_shapes_round_trip() {
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                proof_round_trip(inputs, outputs);
            }
        }
    }

    /// Isolates the largest one-output shape for process-level resource measurements.
    #[test]
    #[ignore = "explicit isolated resource measurement"]
    fn payment_four_by_one_resource_measurement() {
        proof_round_trip(4, 1);
    }

    /// Isolates the priority shape for process-level resource measurements.
    #[test]
    #[ignore = "explicit isolated resource measurement"]
    fn payment_four_by_two_resource_measurement() {
        proof_round_trip(4, 2);
    }

    /// Distinct positions and repeated output occurrences remain valid and separately funded.
    #[test]
    fn payment_repeated_occurrences_and_amount_boundaries() {
        let repeated = fixture::PaymentFixture::with_amounts(&[11, 11], &[11, 11], 0, true);
        assert_eq!(
            repeated.outputs()[0].commitment().unwrap(),
            repeated.outputs()[1].commitment().unwrap()
        );
        let native = repeated.spends();
        assert_ne!(
            repeated.body.inputs().nullifiers()[0],
            repeated.body.inputs().nullifiers()[1]
        );
        assert!(valid_fixture(&repeated));
        let maximum = houseki_types::Amount::MAX_ATOMS;
        let balanced =
            fixture::PaymentFixture::with_amounts(&[maximum; 3], &[maximum; 2], maximum, false);
        assert!(valid_fixture(&balanced));
        houseki_notes::check_payment(
            &balanced.body,
            &balanced.anchor,
            &balanced.spends(),
            &balanced.outputs(),
            crate::profile::payment::body_limits().payment_counts(),
        )
        .unwrap();
        let marker = repeated.body.inputs().nullifiers()[0];
        assert!(
            houseki_types::PaymentInputs::new(
                repeated.anchor.root(),
                vec![marker, marker],
                crate::profile::payment::body_limits().payment_counts()
            )
            .is_err()
        );
        let excessive =
            fixture::PaymentFixture::with_amounts(&[maximum; 4], &[maximum; 2], maximum, false);
        assert!(!valid_fixture(&excessive));
        assert!(
            houseki_notes::check_payment(
                &excessive.body,
                &excessive.anchor,
                &excessive.spends(),
                &excessive.outputs(),
                crate::profile::payment::body_limits().payment_counts()
            )
            .is_err()
        );
        houseki_notes::check_payment(
            &repeated.body,
            &repeated.anchor,
            &native,
            &repeated.outputs(),
            crate::profile::payment::body_limits().payment_counts(),
        )
        .unwrap();
    }

    /// Trusted selectors cover every occurrence and every depth-64 path phase exactly once.
    #[test]
    fn payment_schedule_covers_each_slot_once() {
        use p3_field::PrimeField64;
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let layout =
                    PaymentLayout::for_shape(SupportedPaymentShape::new(inputs, outputs).unwrap())
                        .unwrap();
                let mut counts = vec![0; layout.schedule.selectors()];
                for row in 0..layout.rows() {
                    let phases = layout.schedule.values(row);
                    for (count, value) in counts.iter_mut().zip(&phases) {
                        assert!(value.as_canonical_u64() <= 1);
                        *count += value.as_canonical_u64() as usize;
                    }

                    assert_eq!(
                        phases[301..]
                            .iter()
                            .map(|value| value.as_canonical_u64())
                            .sum::<u64>(),
                        u64::from(row + 1 < layout.schedule.active_rows())
                    );
                }

                assert_eq!(counts[0], inputs + outputs);
                assert_eq!(counts[76], inputs + outputs);
                assert_eq!(counts[78], 128 * (inputs + outputs));
                assert_eq!(counts[79], inputs);
                assert_eq!(counts[167], inputs);
                assert_eq!(counts[188], 64 * inputs);
                assert_eq!(counts[211], inputs);
                assert_eq!(&counts[297..301], &[inputs, inputs, outputs, 1]);
                assert_eq!(&counts[301..301 + inputs], vec![1733; inputs]);
                assert_eq!(&counts[301 + inputs..], vec![129; outputs]);
                for count in &counts[233..297] {
                    assert_eq!(*count, 23 * inputs);
                }
            }
        }
    }

    /// Builds the exact independent statement used by complete relation tests.
    fn statement(fixture: &fixture::PaymentFixture, layout: &PaymentLayout) -> Statement {
        let identity = crate::profile::payment::identity(layout.shape());
        Statement::payment(
            &fixture.body,
            &fixture.anchor,
            fixture.body.context(),
            &identity,
            crate::profile::payment::body_limits(),
        )
        .unwrap()
    }

    /// Checks the full AIR independently from the native conservation precheck.
    fn valid_fixture(fixture: &fixture::PaymentFixture) -> bool {
        let spends = fixture.spends();
        let outputs = fixture.outputs();
        let witness = PaymentWitness::new(&spends, &outputs).unwrap();
        let layout = PaymentLayout::for_shape(
            SupportedPaymentShape::new(spends.len(), outputs.len()).unwrap(),
        )
        .unwrap();
        let air = PaymentAir::new(&layout);
        let statement = statement(fixture, &layout);
        let trace = trace::build(&air, &witness, &statement, &CancellationToken::new()).unwrap();
        check_all_constraints(
            &air,
            &RowMajorMatrix::new(trace.values().to_vec(), layout.width()),
            &statement.public_values,
            Some(1),
        )
        .is_ok()
    }

    /// First, middle and last slots cannot skip, repeat or change an amount or component link.
    #[test]
    fn payment_schedule_rejects_skipped_slots_and_changed_transitions() {
        let fixture = fixture::PaymentFixture::new(4, 2);
        let spends = fixture.spends();
        let outputs = fixture.outputs();
        let witness = PaymentWitness::new(&spends, &outputs).unwrap();
        let layout = PaymentLayout::for_shape(SupportedPaymentShape::new(4, 2).unwrap()).unwrap();
        let air = PaymentAir::new(&layout);
        let statement = statement(&fixture, &layout);
        let trace = trace::build(&air, &witness, &statement, &CancellationToken::new()).unwrap();
        let mut rows = trace.values().to_vec();
        for slot in 0..6 {
            let (start, length) = if slot < 4 {
                (slot * 1733, 1733)
            } else {
                (4 * 1733 + (slot - 4) * 129, 129)
            };
            for (row, column) in [
                (start, 0),
                (start, 32),
                (start, 48),
                (start, 112),
                (start + 127, 184 + 64),
                (start + length - 1, 184 + 16),
                (start + length - 1, 184 + 32),
                (start + length - 1, 184 + 432),
            ] {
                let index = row * layout.width() + column;
                rows[index] += p3_goldilocks::Goldilocks::ONE;
                assert!(
                    !air.valid_row(&rows, &statement.public_values, row)
                        || (row > 0 && !air.valid_row(&rows, &statement.public_values, row - 1)),
                    "slot {slot}, row {row}, column {column}"
                );
                rows[index] -= p3_goldilocks::Goldilocks::ONE;
            }

            let row = start + length - 1;
            let index = row * layout.width() + 184;
            let saved = rows[index..index + 448].to_vec();
            rows[index..index + 448].fill(p3_goldilocks::Goldilocks::ZERO);
            assert!(
                !air.valid_row(&rows, &statement.public_values, row),
                "skipped accumulation {slot}"
            );
            rows[index..index + 448].copy_from_slice(&saved);
            if slot < 4 {
                for (phase, column) in [(128, 184), (216, 176), (217, 112), (239, 184 + 64)] {
                    let row = start + phase;
                    let index = row * layout.width() + column;
                    rows[index] += p3_goldilocks::Goldilocks::ONE;
                    assert!(
                        !air.valid_row(&rows, &statement.public_values, row)
                            || !air.valid_row(&rows, &statement.public_values, row - 1)
                    );
                    rows[index] -= p3_goldilocks::Goldilocks::ONE;
                }
            }
        }

        let fee_row = layout.schedule.active_rows() - 1;
        for (row, column) in [
            (fee_row, 200),
            (fee_row, 216),
            (fee_row + 1, 32),
            (layout.rows() - 1, 184),
            (0, 0),
        ] {
            let index = row * layout.width() + column;
            rows[index] += p3_goldilocks::Goldilocks::ONE;
            assert!(
                !air.valid_row(&rows, &statement.public_values, row)
                    || (row > 0 && !air.valid_row(&rows, &statement.public_values, row - 1))
            );
            rows[index] -= p3_goldilocks::Goldilocks::ONE;
        }

        let fee = fee_row * layout.width() + 200;
        rows[fee] -= p3_goldilocks::Goldilocks::ONE;
        assert!(!air.valid_row(&rows, &statement.public_values, fee_row));
        rows[fee] += p3_goldilocks::Goldilocks::ONE;

        assert!(air.valid_row(&rows, &statement.public_values, layout.rows() - 1));
        assert_ne!(
            rows[..16],
            rows[(layout.rows() - 1) * layout.width()..(layout.rows() - 1) * layout.width() + 16]
        );
    }

    /// Extracts exact next-row reads from the symbolic AIR rather than trusting a hand-written union.
    fn collect_next_columns(
        expression: &p3_air::symbolic::SymbolicExpression<p3_goldilocks::Goldilocks>,
        columns: &mut std::collections::BTreeSet<usize>,
        visited: &mut std::collections::HashSet<
            *const p3_air::symbolic::SymbolicExpression<p3_goldilocks::Goldilocks>,
        >,
    ) {
        use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr};
        if !visited.insert(std::ptr::from_ref(expression)) {
            return;
        }

        match expression {
            SymbolicExpr::Leaf(BaseLeaf::Variable(variable))
                if variable.entry == (BaseEntry::Main { offset: 1 }) =>
            {
                columns.insert(variable.index);
            }

            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                collect_next_columns(x, columns, visited);
                collect_next_columns(y, columns, visited);
            }

            SymbolicExpr::Neg { x, .. } => collect_next_columns(x, columns, visited),
            SymbolicExpr::Leaf(_) => {}
        }
    }
}
