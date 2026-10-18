//! Bounded real proofs of framing, the private sponge and canonical digest extraction.

use crate::backend::{
    BackendError, codec, config::BackendProof, gadget_checks, prover::Request, trace::Trace,
};
use crate::{
    gadgets::HashAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Synthetic complete hash identity distinct from all production statements.
const PREFIX: &[u8] = b"houseki/test/complete-application-hash/v1";

/// Geometry for a seven byte part with private intermediates shared across thirty two rows.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 986,
    quotient_chunks: 8,
    main_next: true,
};

/// Selects trusted fixed metadata for the complete hash fixture.
fn air() -> HashAir {
    HashAir::new(&[7])
}

/// Selects a synthetic codec identity without production admission.
fn identity() -> ExpectedIdentity {
    ExpectedIdentity {
        profile: ProofProfileId::new(0xffff000b),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x6c; 64],
    }
}

/// Assigns public byte fixtures and all private intermediates into protected trace storage.
fn trace() -> Trace {
    let mut trace = Trace::new(512, LAYOUT.width, 512 * LAYOUT.width).unwrap();
    air().assign_trace(&[Goldilocks::from_u8(0xa3); 7], trace.values_mut());

    trace
}

/// Round trips a complete hash proof through the unchanged bounded production codec.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    gadget_checks::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &air(),
            public,
            identity: &identity(),
            layout: LAYOUT,
        },
        trace,
    )
}

/// Complete hash acceptance and cryptographic rejection without public intermediate samples.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use p3_air::{
        BaseAir,
        symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints},
    };
    use p3_uni_stark::get_log_num_quotient_chunks;
    use std::time::Instant;

    /// Measures the entire relation, including private bridges and fixed phase selectors.
    #[test]
    fn gadgets_application_hash_geometry_matches_constraints() {
        let air = air();
        let layout = AirLayout::from_air(&air);

        assert_eq!(air.width(), LAYOUT.width);
        assert_eq!(air.num_public_values(), 71);
        assert_eq!(get_symbolic_constraints(&air, layout).len(), 2858);
        assert_eq!(get_max_constraint_degree(&air, layout, 512), 4);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&air, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// Proves the complete hash under the existing size cap and binds every public endpoint.
    #[test]
    fn gadgets_application_hash_proof_binds_input_and_digest() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let trace = trace();
        let public = air().public(trace.values());

        let start = Instant::now();
        let proof = prove(&lease, trace, &public).unwrap();
        let prove_time = start.elapsed();

        let start = Instant::now();
        verifier::verify(&lease, PREFIX, &air(), &proof, &public).unwrap();
        let verify_time = start.elapsed();

        let encoded = codec::encode(&identity(), LAYOUT, &proof).unwrap();
        println!(
            "complete application hash synthetic proof: {} bytes, prove+codec {} ms, verify {} ms",
            encoded.as_bytes().len(),
            prove_time.as_millis(),
            verify_time.as_millis()
        );

        for index in 0..71 {
            let mut changed = public.clone();
            changed[index] += Goldilocks::ONE;

            assert!(verifier::verify(&lease, PREFIX, &air(), &proof, &changed).is_err());
        }
    }

    /// Recomputing extraction for forged private samples cannot produce a valid hash proof.
    #[test]
    fn gadgets_application_hash_recomputed_forgery_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let air = air();
        let mut forged = trace();
        for row in forged.values_mut().as_chunks_mut::<986>().0 {
            row[air.frame_width()] += Goldilocks::ONE;
        }

        air.reassign_extraction(forged.values_mut());
        let public = air.public(forged.values());
        let result = prove(&lease, forged, &public);

        #[cfg(debug_assertions)]
        assert!(matches!(result, Err(BackendError::ProvingFailed)));

        #[cfg(not(debug_assertions))]
        {
            let proof = result.expect("release prover must reach cryptographic verification");
            assert!(matches!(
                verifier::verify(&lease, PREFIX, &air, &proof, &public),
                Err(BackendError::InvalidProof)
            ));
        }
    }
}
