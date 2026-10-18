//! Real bounded proofs of eleven canonical samples and their 512 bit integer digest.

use crate::backend::{
    BackendError, codec, config::BackendProof, gadget_checks, prover::Request, trace::Trace,
};
use crate::{
    gadgets::ExtractionRowAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Synthetic extraction identity excluded from production statement admission.
const PREFIX: &[u8] = b"houseki/test/integer-digest-extraction/v1";

/// Sixteen row extraction cycles with bounded per-row width and linked carries.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 877,
    quotient_chunks: 8,
    main_next: true,
};

/// Selects a synthetic codec identity without introducing a production dispatch route.
fn identity() -> ExpectedIdentity {
    ExpectedIdentity {
        profile: ProofProfileId::new(0xffff000a),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x6b; 64],
    }
}

/// Assigns complete extraction cycles from maximal canonical samples into protected storage.
fn trace() -> Trace {
    let mut trace = Trace::new(512, LAYOUT.width, 512 * LAYOUT.width).unwrap();
    ExtractionRowAir::assign_trace(&[Goldilocks::NEG_ONE; 11], trace.values_mut());

    trace
}

/// Reads only the synthetic public samples and expected output bytes.
fn public(trace: &Trace) -> Vec<Goldilocks> {
    let mut public = trace.values()[..11].to_vec();
    for row in trace.values().as_chunks::<877>().0.iter().take(16) {
        public.extend_from_slice(&row[825..829]);
    }

    public
}

/// Round trips a real hidden proof through the existing bounded codec.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    gadget_checks::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &ExtractionRowAir,
            public,
            identity: &identity(),
            layout: LAYOUT,
        },
        trace,
    )
}

/// Proof geometry, endpoint binding and cryptographic rejection of malicious extraction cells.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use p3_air::{
        BaseAir,
        symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints},
    };
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// Measures the fixed selectors and linked carries against the bounded proof layout.
    #[test]
    fn gadgets_extraction_geometry_matches_constraints() {
        let layout = AirLayout::from_air(&ExtractionRowAir);

        assert_eq!(ExtractionRowAir.width(), LAYOUT.width);
        assert_eq!(
            get_symbolic_constraints(&ExtractionRowAir, layout).len(),
            1767
        );
        assert_eq!(get_max_constraint_degree(&ExtractionRowAir, layout, 512), 3);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&ExtractionRowAir, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// A real extraction proof binds all eleven canonical samples and sixty four output bytes.
    #[test]
    fn gadgets_extraction_proof_binds_samples_and_digest() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let trace = trace();
        let public = public(&trace);
        let proof = prove(&lease, trace, &public).unwrap();
        verifier::verify(&lease, PREFIX, &ExtractionRowAir, &proof, &public).unwrap();
        let encoded = codec::encode(&identity(), LAYOUT, &proof).unwrap();
        println!(
            "integer extraction synthetic proof: {} bytes",
            encoded.as_bytes().len()
        );

        for index in 0..75 {
            let mut changed = public.clone();
            changed[index] += Goldilocks::ONE;

            assert!(verifier::verify(&lease, PREFIX, &ExtractionRowAir, &proof, &changed).is_err());
        }
    }

    /// The verifier rejects broken carry transitions and non-Boolean signed carry witnesses.
    #[test]
    fn gadgets_extraction_malicious_carries_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        for column in [861, 876] {
            let mut forged = trace();
            forged.values_mut()[877 + column] += Goldilocks::ONE;
            let public = public(&forged);
            let result = prove(&lease, forged, &public);

            #[cfg(debug_assertions)]
            assert!(matches!(result, Err(BackendError::ProvingFailed)));

            #[cfg(not(debug_assertions))]
            {
                let proof = result.expect("release prover must reach cryptographic verification");
                assert!(matches!(
                    verifier::verify(&lease, PREFIX, &ExtractionRowAir, &proof, &public),
                    Err(BackendError::InvalidProof)
                ));
            }
        }
    }
}
