//! Real complete recipient hash proofs under the existing protected backend and codec.

use super::{
    BackendError, codec, config::BackendProof, gadget_proof, prover::Request, trace::Trace,
};
use crate::{
    gadgets::RecipientHashAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Synthetic identity with complete recipient input lengths and no production admission.
const PREFIX: &[u8] = b"houseki/test/complete-recipient-hash/v1";

/// Repeats eight sixty four row schedules using one bounded shared work region.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 909,
    quotient_chunks: 8,
    main_next: true,
};

/// Separates this complete relation from component and production codec identities.
fn identity() -> ExpectedIdentity {
    ExpectedIdentity {
        profile: ProofProfileId::new(0xffff000d),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x6e; 64],
    }
}

/// Assigns the native vector's full public input into protected trace storage.
fn trace() -> Trace {
    let mut input = [Goldilocks::ZERO; 1636];
    for (index, value) in input[..64].iter_mut().enumerate() {
        *value = Goldilocks::from_usize(index);
    }

    input[64] = Goldilocks::ONE;
    input[1604..].fill(Goldilocks::from_u8(255));
    let mut trace = Trace::new(512, LAYOUT.width, 512 * LAYOUT.width).unwrap();
    RecipientHashAir::new().assign_trace(&input, trace.values_mut());

    trace
}

/// Proves and round trips the full relation through the unchanged bounded codec.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    gadget_proof::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &RecipientHashAir::new(),
            public,
            identity: &identity(),
            layout: LAYOUT,
        },
        trace,
    )
}

/// Cryptographic acceptance, endpoint binding and coordinated forged-phase rejection.
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

    /// The codec geometry includes the full trusted schedule, bridges and scratch constraints.
    #[test]
    fn gadgets_recipient_hash_geometry_matches_constraints() {
        let air = RecipientHashAir::new();
        let layout = AirLayout::from_air(&air);

        assert_eq!(air.width(), LAYOUT.width);
        assert_eq!(air.num_public_values(), 1700);
        assert_eq!(get_symbolic_constraints(&air, layout).len(), 20985);
        assert_eq!(get_max_constraint_degree(&air, layout, 512), 4);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&air, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// A real proof binds network, suite, complete key and digest under the existing size cap.
    #[test]
    fn gadgets_recipient_hash_proof_binds_input_and_digest() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let air = RecipientHashAir::new();
        let trace = trace();
        let public = air.public(trace.values());
        let start = Instant::now();
        let proof = prove(&lease, trace, &public).unwrap();
        let prove_time = start.elapsed();

        let start = Instant::now();
        verifier::verify(&lease, PREFIX, &air, &proof, &public).unwrap();
        let verify_time = start.elapsed();
        let encoded = codec::encode(&identity(), LAYOUT, &proof).unwrap();
        println!(
            "complete recipient hash synthetic proof: {} bytes, prove+codec {} ms, verify {} ms",
            encoded.as_bytes().len(),
            prove_time.as_millis(),
            verify_time.as_millis()
        );

        for index in [0, 63, 64, 67, 68, 835, 1603, 1604, 1635, 1636, 1699] {
            let mut changed = public.clone();
            changed[index] += Goldilocks::ONE;

            assert!(
                verifier::verify(&lease, PREFIX, &air, &proof, &changed).is_err(),
                "endpoint {index}"
            );
        }
    }

    /// Recomputed permutations or extraction cannot conceal broken private phase links.
    #[test]
    fn gadgets_recipient_hash_recomputed_forgeries_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let air = RecipientHashAir::new();
        for transition in [true, false] {
            let mut forged = trace();
            if transition {
                for cycle in forged
                    .values_mut()
                    .as_chunks_mut::<{ 64 * LAYOUT.width }>()
                    .0
                {
                    cycle[17 * LAYOUT.width + 11] += Goldilocks::ONE;
                }

                air.reassign_sponge(forged.values_mut(), 17);
            } else {
                for row in forged.values_mut().as_chunks_mut::<{ LAYOUT.width }>().0 {
                    row[7] += Goldilocks::ONE;
                }

                air.reassign_extraction(forged.values_mut());
            }

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
}
