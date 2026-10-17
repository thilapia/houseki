//! Real proofs composing application framing and the eleven sample sponge relation.

use super::{
    BackendError, codec, config::BackendProof, gadget_proof, prover::Request, trace::Trace,
};
use crate::{
    gadgets::FramedSpongeAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Synthetic composition identity without production statement admission.
const PREFIX: &[u8] = b"houseki/test/framed-poseidon2-samples/v1";

/// Bounded geometry for two absorbed blocks, one squeeze and their exact framing cells.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 1045,
    quotient_chunks: 8,
    main_next: false,
};

/// Selects a synthetic codec identity distinct from every production profile.
fn identity() -> ExpectedIdentity {
    ExpectedIdentity {
        profile: ProofProfileId::new(0xffff0009),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x6a; 64],
    }
}

/// Assigns public fixtures into protected storage with shared framing and absorption cells.
fn trace() -> Trace {
    let mut trace = Trace::new(512, LAYOUT.width, 512 * LAYOUT.width).unwrap();
    for row in trace.values_mut().as_chunks_mut::<1045>().0 {
        FramedSpongeAir::assign_row(&[Goldilocks::from_u8(0xa3); 8], row);
    }

    trace
}

/// Reads public test endpoints without exposing intermediate hash state in the statement.
fn public(trace: &Trace) -> Vec<Goldilocks> {
    trace.values()[..8]
        .iter()
        .chain(&trace.values()[1034..1045])
        .copied()
        .collect()
}

/// Round trips a real hidden proof through the unchanged bounded codec.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    gadget_proof::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &FramedSpongeAir,
            public,
            identity: &identity(),
            layout: LAYOUT,
        },
        trace,
    )
}

/// Complete composition acceptance and verifier rejection of malicious shared cells.
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

    /// Measures the actual constraints and hiding quotient geometry used by the test codec.
    #[test]
    fn gadgets_framed_sponge_geometry_matches_constraints() {
        let layout = AirLayout::from_air(&FramedSpongeAir);

        assert_eq!(FramedSpongeAir.width(), LAYOUT.width);
        assert_eq!(
            get_symbolic_constraints(&FramedSpongeAir, layout).len(),
            1064
        );
        assert_eq!(get_max_constraint_degree(&FramedSpongeAir, layout, 512), 3);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&FramedSpongeAir, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// Binds bytes and all eleven samples through a real proof within the existing size cap.
    #[test]
    fn gadgets_framed_sponge_proof_binds_bytes_and_samples() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let trace = trace();
        let public = public(&trace);

        let start = Instant::now();
        let proof = prove(&lease, trace, &public).unwrap();
        let prove_time = start.elapsed();

        let start = Instant::now();
        verifier::verify(&lease, PREFIX, &FramedSpongeAir, &proof, &public).unwrap();
        let verify_time = start.elapsed();

        let encoded = codec::encode(&identity(), LAYOUT, &proof).unwrap();
        println!(
            "framed sponge synthetic proof: {} bytes, prove+codec {} ms, verify {} ms",
            encoded.as_bytes().len(),
            prove_time.as_millis(),
            verify_time.as_millis()
        );

        for index in 0..19 {
            let mut changed = public.clone();
            changed[index] += Goldilocks::ONE;

            assert!(verifier::verify(&lease, PREFIX, &FramedSpongeAir, &proof, &changed).is_err());
        }
    }

    /// Downstream reassignment cannot hide forged padding, and a forged cube cannot verify.
    #[test]
    fn gadgets_framed_sponge_malicious_witnesses_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        for padding in [false, true] {
            let mut forged = trace();
            for row in forged.values_mut().as_chunks_mut::<1045>().0 {
                if padding {
                    row[85] += Goldilocks::ONE;
                    FramedSpongeAir::reassign_sponge(row);
                } else {
                    row[134] += Goldilocks::ONE;
                }
            }

            let public = public(&forged);
            let result = prove(&lease, forged, &public);

            #[cfg(debug_assertions)]
            assert!(matches!(result, Err(BackendError::ProvingFailed)));

            #[cfg(not(debug_assertions))]
            {
                let proof = result.expect("release prover must reach cryptographic verification");
                assert!(matches!(
                    verifier::verify(&lease, PREFIX, &FramedSpongeAir, &proof, &public),
                    Err(BackendError::InvalidProof)
                ));
            }
        }
    }
}
