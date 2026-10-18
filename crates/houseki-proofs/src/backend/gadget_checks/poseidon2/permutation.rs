//! Real proof coverage for the pinned application Poseidon2 permutation.

use crate::backend::{
    BackendError, codec, config::BackendProof, gadget_checks, prover::Request, trace::Trace,
};
use crate::{
    gadgets::PermutationAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Synthetic identity excluded from production statement admission.
const PREFIX: &[u8] = b"houseki/test/poseidon2-permutation/v1";

/// Geometry for a complete degree three permutation with hidden trace commitments.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 332,
    quotient_chunks: 8,
    main_next: false,
};

/// Assigns repeated public fixtures into the backend's protected trace allocation.
fn trace() -> Trace {
    let input = std::array::from_fn(|index| Goldilocks::from_usize(index + 1));
    let mut trace = Trace::new(512, LAYOUT.width, 512 * LAYOUT.width).unwrap();
    for row in trace.values_mut().as_chunks_mut::<332>().0 {
        PermutationAir::assign_row(&input, row);
    }

    trace
}

/// Exercises the bounded production codec using a synthetic test identity.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff0008),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x69; 64],
    };

    gadget_checks::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &PermutationAir,
            public,
            identity: &identity,
            layout: LAYOUT,
        },
        trace,
    )
}

/// Real acceptance, endpoint binding and cryptographic rejection of malformed helpers.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use p3_air::{
        BaseAir,
        symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints},
    };
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// Measures the compiled relation against the fixed bounded proof geometry.
    #[test]
    fn gadgets_permutation_geometry_matches_constraints() {
        let layout = AirLayout::from_air(&PermutationAir);

        assert_eq!(PermutationAir.width(), LAYOUT.width);
        assert_eq!(get_symbolic_constraints(&PermutationAir, layout).len(), 348);
        assert_eq!(get_max_constraint_degree(&PermutationAir, layout, 512), 3);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&PermutationAir, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// A valid hidden permutation proof binds every public input and output coordinate.
    #[test]
    fn gadgets_permutation_proof_binds_both_endpoints() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let trace = trace();
        let public = trace.values()[..32].to_vec();
        let proof = prove(&lease, trace, &public).unwrap();
        verifier::verify(&lease, PREFIX, &PermutationAir, &proof, &public).unwrap();

        for index in 0..32 {
            let mut changed = public.clone();
            changed[index] += Goldilocks::ONE;

            assert!(verifier::verify(&lease, PREFIX, &PermutationAir, &proof, &changed).is_err());
        }
    }

    /// Requires release proof construction before the verifier rejects a forged cube.
    #[test]
    fn gadgets_permutation_forged_helper_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let mut forged = trace();
        for row in forged.values_mut().as_chunks_mut::<332>().0 {
            row[32] += Goldilocks::ONE;
        }

        let public = forged.values()[..32].to_vec();
        let result = prove(&lease, forged, &public);

        #[cfg(debug_assertions)]
        assert!(matches!(result, Err(BackendError::ProvingFailed)));

        #[cfg(not(debug_assertions))]
        {
            let proof = result.expect("release prover must reach cryptographic verification");
            assert!(matches!(
                verifier::verify(&lease, PREFIX, &PermutationAir, &proof, &public),
                Err(BackendError::InvalidProof)
            ));
        }
    }
}
