//! Real backend exercises for the shared byte gadget using public test fixtures.

use crate::backend::{
    BackendError, codec, config::BackendProof, gadget_checks, prover::Request, trace::Trace,
};
use crate::{
    gadgets::{ByteAir, assign_byte},
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Domain reserved for this test relation, with no production dispatch entry.
const PREFIX: &[u8] = b"houseki/test/byte/v1";

/// Exact geometry of the isolated byte relation under the hiding backend.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 9,
    quotient_chunks: 4,
    main_next: false,
};

/// Assigns only public fixtures into the same protected storage used by the prover.
fn trace(byte: u8) -> Trace {
    let mut trace = Trace::new(512, 9, 512 * 9).unwrap();
    for row in trace.values_mut().as_chunks_mut::<9>().0 {
        let (value, bits) = row.split_at_mut(1);
        value[0] = Goldilocks::from_u8(byte);
        assign_byte(&value[0], bits.try_into().unwrap()).unwrap();
    }

    trace
}

/// Traverses protected proving and bounded canonical decoding before verification.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff0006),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x62; 64],
    };
    gadget_checks::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &ByteAir,
            public,
            identity: &identity,
            layout: LAYOUT,
        },
        trace,
    )
}

/// Real proof acceptance, binding and malformed witness rejection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use p3_air::symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints};
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// Checks the test codec geometry against the actual symbolic constraints.
    #[test]
    fn gadgets_byte_geometry_matches_constraints() {
        let layout = AirLayout::from_air(&ByteAir);
        let constraints = get_symbolic_constraints(&ByteAir, layout);

        assert_eq!(constraints.len(), 10);
        assert_eq!(get_max_constraint_degree(&ByteAir, layout, 512), 2);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&ByteAir, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// Verifies real proofs at both boundaries and an asymmetric interior value.
    #[test]
    fn gadgets_byte_proofs_bind_expected_value_and_transcript() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        for byte in [0, 0x96, 255] {
            let public = [Goldilocks::from_u8(byte)];
            let proof = prove(&lease, trace(byte), &public).unwrap();

            verifier::verify(&lease, PREFIX, &ByteAir, &proof, &public).unwrap();
            assert!(
                verifier::verify(
                    &lease,
                    PREFIX,
                    &ByteAir,
                    &proof,
                    &[public[0] + Goldilocks::ONE],
                )
                .is_err()
            );
            assert!(
                verifier::verify(&lease, b"changed byte domain", &ByteAir, &proof, &public)
                    .is_err()
            );
        }
    }

    /// Bypasses honest assignment and attempts two independent constraint omissions.
    #[test]
    fn gadgets_byte_malformed_traces_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        for (value, first_bit) in [(256, 0), (2, 2)] {
            let mut forged = trace(0);
            for row in forged.values_mut().as_chunks_mut::<9>().0 {
                row[0] = Goldilocks::from_u16(value);
                row[1] = Goldilocks::from_u16(first_bit);
            }

            let public = [Goldilocks::from_u16(value)];
            let result = prove(&lease, forged, &public);

            #[cfg(debug_assertions)]
            assert!(matches!(result, Err(BackendError::ProvingFailed)));

            #[cfg(not(debug_assertions))]
            {
                let proof = result.expect("release prover must reach cryptographic verification");
                assert!(matches!(
                    verifier::verify(&lease, PREFIX, &ByteAir, &proof, &public),
                    Err(BackendError::InvalidProof)
                ));
            }
        }
    }
}
