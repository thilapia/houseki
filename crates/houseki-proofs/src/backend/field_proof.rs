//! Real proof checks for canonical scalar encodings and forged modulus aliases.

use super::{
    BackendError, codec, config::BackendProof, gadget_proof, prover::Request, trace::Trace,
};
use crate::{
    gadgets::FieldAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Domain reserved for this test relation without production profile admission.
const PREFIX: &[u8] = b"houseki/test/field-bytes/v1";

/// Exact original trace geometry for the isolated canonical scalar relation.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 75,
    quotient_chunks: 4,
    main_next: false,
};

/// Assigns a public scalar fixture directly into protected trace storage.
fn trace(word: u64) -> Trace {
    let value = Goldilocks::from_u64(word);
    let mut trace = Trace::new(512, 75, 512 * 75).unwrap();
    for row in trace.values_mut().as_chunks_mut::<75>().0 {
        FieldAir::assign_row(&value, row);
    }

    trace
}

/// Encodes and decodes a proof using the bounded backend path and this test's identity.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff0006),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x64; 64],
    };
    gadget_proof::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &FieldAir,
            public,
            identity: &identity,
            layout: LAYOUT,
        },
        trace,
    )
}

/// Backend acceptance at canonical boundaries and cryptographic rejection of malformed rows.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use p3_air::symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints};
    use p3_field::PrimeField64;
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// Confirms that canonicality needs only quadratic constraints and four hiding chunks.
    #[test]
    fn gadgets_field_geometry_matches_constraints() {
        let layout = AirLayout::from_air(&FieldAir);

        assert_eq!(get_symbolic_constraints(&FieldAir, layout).len(), 79);
        assert_eq!(get_max_constraint_degree(&FieldAir, layout, 512), 2);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&FieldAir, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// Real proofs cover both canonicality branches and bind the expected scalar.
    #[test]
    fn gadgets_field_proofs_bind_boundary_values() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        for word in [0, Goldilocks::ORDER_U64 - 2, Goldilocks::ORDER_U64 - 1] {
            let public = [Goldilocks::from_u64(word)];
            let proof = prove(&lease, trace(word), &public).unwrap();

            verifier::verify(&lease, PREFIX, &FieldAir, &proof, &public).unwrap();
            assert!(
                verifier::verify(
                    &lease,
                    PREFIX,
                    &FieldAir,
                    &proof,
                    &[public[0] + Goldilocks::ONE],
                )
                .is_err()
            );
        }
    }

    /// An encoding of the modulus with valid byte ranges cannot prove the scalar zero.
    #[test]
    fn gadgets_field_modulus_alias_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let mut forged = trace(Goldilocks::ORDER_U64 - 1);
        for row in forged.values_mut().as_chunks_mut::<75>().0 {
            row[0] = Goldilocks::ZERO;
            row[1] = Goldilocks::ONE;
            row[9] = Goldilocks::ONE;
        }

        reject(&lease, forged, Goldilocks::ZERO);
    }

    /// Both a false maximum indicator and an unconstrained unused inverse reach rejection.
    #[test]
    fn gadgets_field_forged_helpers_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let mut false_maximum = trace(0);
        for row in false_maximum.values_mut().as_chunks_mut::<75>().0 {
            row[73] = Goldilocks::ONE;
            row[74] = Goldilocks::ZERO;
        }

        reject(&lease, false_maximum, Goldilocks::ZERO);

        let mut unused_inverse = trace(Goldilocks::ORDER_U64 - 1);
        for row in unused_inverse.values_mut().as_chunks_mut::<75>().0 {
            row[74] = Goldilocks::ONE;
        }

        reject(&lease, unused_inverse, Goldilocks::NEG_ONE);
    }

    /// Requires actual verifier rejection in release, after malformed proof construction succeeds.
    fn reject(admission: &Admission<'_>, trace: Trace, value: Goldilocks) {
        let public = [value];
        let result = prove(admission, trace, &public);

        #[cfg(debug_assertions)]
        assert!(matches!(result, Err(BackendError::ProvingFailed)));

        #[cfg(not(debug_assertions))]
        {
            let proof = result.expect("release prover must reach cryptographic verification");
            assert!(matches!(
                verifier::verify(admission, PREFIX, &FieldAir, &proof, &public),
                Err(BackendError::InvalidProof)
            ));
        }
    }
}
