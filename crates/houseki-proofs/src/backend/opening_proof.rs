//! Complete private opening proofs through protected execution and the bounded wire codec.

use super::{
    BackendError, codec, config::BackendProof, gadget_proof, opening_statement::statement,
    prover::Request, trace::Trace,
};
use crate::{
    gadgets::{Opening, OpeningAir, OpeningFixture},
    profile::ExpectedIdentity,
    runtime::Admission,
    statement::Statement,
};

/// Four independent 128-row cycles under the backend's minimum hiding geometry.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: Opening::WIDTH,
    quotient_chunks: 8,
    main_next: true,
};

/// Assigns deterministic public fixtures directly into protected trace storage.
fn trace(fixture: &OpeningFixture) -> Trace {
    let mut trace = Trace::new(512, LAYOUT.width, 512 * LAYOUT.width).unwrap();
    Opening::new()
        .assign(fixture.view(), trace.values_mut())
        .unwrap();

    trace
}

/// Uses a verifier-reconstructed native statement and a test-only complete-opening AIR.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    identity: &ExpectedIdentity,
    statement: &Statement,
) -> Result<BackendProof, BackendError> {
    gadget_proof::prove(
        admission,
        Request {
            prefix: &statement.prefix,
            air: &OpeningAir::new(),
            public: &statement.public_values,
            identity,
            layout: LAYOUT,
        },
        trace,
    )
}

/// Cryptographic acceptance, public bindings and coordinated invalid witness rejection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use p3_air::{
        BaseAir,
        symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints},
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_uni_stark::get_log_num_quotient_chunks;
    use std::time::Instant;

    /// Codec quotient geometry accounts for the full opening schedule and all validity constraints.
    #[test]
    fn gadgets_opening_geometry_matches_constraints() {
        let air = OpeningAir::new();
        let layout = AirLayout::from_air(&air);
        let constraints = get_symbolic_constraints(&air, layout).len();
        println!(
            "complete opening geometry: {} columns, 512 rows, {} constraints, {} public values",
            air.width(),
            constraints,
            air.num_public_values()
        );
        assert_eq!(air.width(), LAYOUT.width);
        assert_eq!(air.num_public_values(), 144);
        assert_eq!(constraints, 55832);
        assert_eq!(get_max_constraint_degree(&air, layout, 512), 4);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&air, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// A complete real proof binds the native body, every semantic field and opaque envelope bytes.
    #[test]
    fn gadgets_complete_opening_proof_binds_native_statement() {
        let fixture = OpeningFixture::new(1);
        let (identity, expected) = statement(&fixture, 0, 1, 0, 7);
        assert_eq!(&expected.public_values, &fixture.public);
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let trace = trace(&fixture);
        let start = Instant::now();
        let proof = prove(&lease, trace, &identity, &expected).unwrap();
        let prove_time = start.elapsed();
        let start = Instant::now();
        verifier::verify(
            &lease,
            &expected.prefix,
            &OpeningAir::new(),
            &proof,
            &expected.public_values,
        )
        .unwrap();
        let verify_time = start.elapsed();
        let encoded = codec::encode(&identity, LAYOUT, &proof).unwrap();
        println!(
            "complete opening synthetic proof: {} bytes, prove+codec {} ms, verify {} ms",
            encoded.as_bytes().len(),
            prove_time.as_millis(),
            verify_time.as_millis()
        );

        for index in [0, 63, 64, 72, 79, 80, 143] {
            let mut public = expected.public_values.clone();
            public[index] += Goldilocks::ONE;
            assert!(
                verifier::verify(
                    &lease,
                    &expected.prefix,
                    &OpeningAir::new(),
                    &proof,
                    &public
                )
                .is_err()
            );
        }

        let (_, changed) = statement(&fixture, 0, 1, 0, 8);
        assert_eq!(expected.public_values, changed.public_values);
        assert_ne!(expected.prefix, changed.prefix);
        assert!(
            verifier::verify(
                &lease,
                &changed.prefix,
                &OpeningAir::new(),
                &proof,
                &changed.public_values
            )
            .is_err()
        );
    }

    /// Recomputed noncanonical key hashes and substituted recipient digests reach verifier rejection.
    #[test]
    fn gadgets_complete_opening_forgeries_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let air = OpeningAir::new();
        for substitute in [false, true] {
            let mut fixture = OpeningFixture::new(0);
            let mut forged = trace(&fixture);
            if !substitute {
                fixture.input[140..143].copy_from_slice(&[1, 13, 0].map(Goldilocks::from_u8));
            }

            fixture.rehash(&air.opening, forged.values_mut(), substitute);
            let (identity, expected) = statement(&fixture, 0, 1, 0, 7);
            let result = prove(&lease, forged, &identity, &expected);
            #[cfg(debug_assertions)]
            assert!(matches!(result, Err(BackendError::ProvingFailed)));

            #[cfg(not(debug_assertions))]
            {
                let proof = result.expect("release prover must reach cryptographic verification");
                assert!(matches!(
                    verifier::verify(
                        &lease,
                        &expected.prefix,
                        &air,
                        &proof,
                        &expected.public_values
                    ),
                    Err(BackendError::InvalidProof)
                ));
            }
        }
    }
}
