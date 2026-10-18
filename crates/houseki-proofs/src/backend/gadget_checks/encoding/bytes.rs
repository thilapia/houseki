//! Backend verification of complete identifiers under the shared byte range gadget.

use crate::backend::{
    BackendError, codec, config::BackendProof, gadget_checks, prover::Request, trace::Trace,
};
use crate::{
    gadgets::{BytesAir, assign_bytes},
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Domain reserved for complete identifier fixtures with no production profile admission.
const PREFIX: &[u8] = b"houseki/test/bytes64/v1";

/// Original trace geometry before hiding rows and columns are added by the backend.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 576,
    quotient_chunks: 4,
    main_next: false,
};

/// Writes every public fixture byte and bit into protected prover storage.
fn trace(values: &[Goldilocks; 64]) -> Trace {
    let mut trace = Trace::new(512, 576, 512 * 576).unwrap();
    for row in trace.values_mut().as_chunks_mut::<576>().0 {
        let (bytes, bits) = row.split_at_mut(64);
        bytes.copy_from_slice(values);
        assign_bytes(values, bits.as_chunks_mut::<8>().0.try_into().unwrap()).unwrap();
    }

    trace
}

/// Proves the test relation through protected encoding and bounded decoding.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff0006),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x63; 64],
    };
    gadget_checks::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &BytesAir::<64>,
            public,
            identity: &identity,
            layout: LAYOUT,
        },
        trace,
    )
}

/// Full identifier binding and independent malformed trace rejection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use p3_air::symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints};
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// Accounts for every byte, Boolean bit and public equality in the test geometry.
    #[test]
    fn gadgets_bytes_geometry_matches_constraints() {
        let air = BytesAir::<64>;
        let layout = AirLayout::from_air(&air);

        assert_eq!(get_symbolic_constraints(&air, layout).len(), 640);
        assert_eq!(get_max_constraint_degree(&air, layout, 512), 2);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&air, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// A real proof retains the final identifier byte and the exact expected length.
    #[test]
    fn gadgets_bytes_proof_binds_full_identifier() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let public = std::array::from_fn(|index| Goldilocks::from_u8(index as u8 * 4));
        let proof = prove(&lease, trace(&public), &public).unwrap();

        verifier::verify(&lease, PREFIX, &BytesAir::<64>, &proof, &public).unwrap();

        let mut changed = public;
        changed[63] += Goldilocks::ONE;

        assert!(verifier::verify(&lease, PREFIX, &BytesAir::<64>, &proof, &changed).is_err());
        assert!(verifier::verify(&lease, PREFIX, &BytesAir::<64>, &proof, &public[..63]).is_err());
    }

    /// A non-Boolean bit in the last byte cannot pass by reconstructing the same byte.
    #[test]
    fn gadgets_bytes_malformed_final_byte_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let mut public = [Goldilocks::ZERO; 64];
        public[63] = Goldilocks::TWO;
        let mut forged = trace(&[Goldilocks::ZERO; 64]);
        for row in forged.values_mut().as_chunks_mut::<576>().0 {
            row[63] = Goldilocks::TWO;
            row[64 + 63 * 8] = Goldilocks::TWO;
        }

        let result = prove(&lease, forged, &public);

        #[cfg(debug_assertions)]
        assert!(matches!(result, Err(BackendError::ProvingFailed)));

        #[cfg(not(debug_assertions))]
        {
            let proof = result.expect("release prover must reach cryptographic verification");
            assert!(matches!(
                verifier::verify(&lease, PREFIX, &BytesAir::<64>, &proof, &public),
                Err(BackendError::InvalidProof)
            ));
        }
    }
}
