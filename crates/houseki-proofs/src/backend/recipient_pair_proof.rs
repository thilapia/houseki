//! Real proof checks for canonical ML-KEM recipient coefficient pairs.

use super::{
    BackendError, codec, config::BackendProof, gadget_proof, prover::Request, trace::Trace,
};
use crate::{
    gadgets::RecipientPairAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Separates this synthetic coefficient relation from every admitted production transcript.
const PREFIX: &[u8] = b"houseki/test/recipient-coefficients/v1";

/// Fixed geometry of the quadratic pair relation through the existing protected backend.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: RecipientPairAir::WIDTH,
    quotient_chunks: 4,
    main_next: false,
};

/// Assigns public fixture bytes directly into the cleanup-owning trace buffer.
fn trace(bytes: [u8; 3]) -> Trace {
    let values = bytes.map(Goldilocks::from_u8);
    let mut trace = Trace::new(512, 51, 512 * 51).unwrap();
    for row in trace.values_mut().as_chunks_mut::<51>().0 {
        RecipientPairAir::assign_row(&values, row).unwrap();
    }

    trace
}

/// Proves and round-trips the bounded codec under an explicitly synthetic identity.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff000e),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x6f; 64],
    };
    gadget_proof::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &RecipientPairAir,
            public,
            identity: &identity,
            layout: LAYOUT,
        },
        trace,
    )
}

/// Boundary proofs and cryptographic rejection without the honest native validator.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use p3_air::symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints};
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// The fixed codec layout matches the actual bound and public-link equations.
    #[test]
    fn gadgets_recipient_pair_geometry_matches_constraints() {
        let air = RecipientPairAir;
        let layout = AirLayout::from_air(&air);

        assert_eq!(get_symbolic_constraints(&air, layout).len(), 56);
        assert_eq!(get_max_constraint_degree(&air, layout, 512), 2);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&air, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// Both packing positions accept zero and the cap while binding every public byte.
    #[test]
    fn gadgets_recipient_pair_proofs_accept_boundaries_and_bind_bytes() {
        let runtime = ProofRuntime::new();
        let admission = runtime.acquire().unwrap();
        for bytes in [[0x00, 0x00, 0xd0], [0x00, 0x0d, 0x00]] {
            let public = bytes.map(Goldilocks::from_u8);
            let proof = prove(&admission, trace(bytes), &public).unwrap();
            verifier::verify(&admission, PREFIX, &RecipientPairAir, &proof, &public).unwrap();

            for index in 0..3 {
                let mut changed = public;
                changed[index] += Goldilocks::ONE;
                assert!(matches!(
                    verifier::verify(&admission, PREFIX, &RecipientPairAir, &proof, &changed),
                    Err(BackendError::InvalidProof)
                ));
            }
        }
    }

    /// Wrapped differences and negative field differences both fail for either coefficient.
    #[test]
    fn gadgets_recipient_pair_noncanonical_coefficients_cannot_verify() {
        let runtime = ProofRuntime::new();
        let admission = runtime.acquire().unwrap();
        for slot in 0..2 {
            for negative in [false, true] {
                let mut forged = trace([0, 0x0d, 0xd0]);
                for row in forged.values_mut().as_chunks_mut::<51>().0 {
                    // Increment one coefficient from 3328 to 3329 with consistent byte bits.
                    let (byte, bit) = if slot == 0 { (0, 0) } else { (1, 4) };
                    row[byte] += Goldilocks::from_u16(1 << bit);
                    row[3 + byte * 8 + bit] = Goldilocks::ONE;

                    let difference = &mut row[27 + slot * 12..39 + slot * 12];
                    if negative {
                        difference.fill(Goldilocks::ZERO);
                        difference[0] = Goldilocks::NEG_ONE;
                    } else {
                        difference.fill(Goldilocks::ONE);
                    }
                }

                reject(&admission, forged);
            }
        }
    }

    /// Release tests must construct an encoded malformed proof and reach verifier rejection.
    fn reject(admission: &Admission<'_>, trace: Trace) {
        let public = trace.values()[..3].to_vec();
        let result = prove(admission, trace, &public);

        #[cfg(debug_assertions)]
        assert!(matches!(result, Err(BackendError::ProvingFailed)));

        #[cfg(not(debug_assertions))]
        {
            let proof = result.expect("release prover must reach cryptographic verification");
            assert!(matches!(
                verifier::verify(admission, PREFIX, &RecipientPairAir, &proof, &public),
                Err(BackendError::InvalidProof)
            ));
        }
    }
}
