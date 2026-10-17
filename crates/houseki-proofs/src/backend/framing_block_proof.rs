//! Real bounded proofs of one block from the full recipient-binding transcript.

use super::{
    BackendError, codec, config::BackendProof, gadget_proof, prover::Request, trace::Trace,
};
use crate::{
    gadgets::BlockAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Synthetic block relation, distinct from complete hashes and production families.
const PREFIX: &[u8] = b"houseki/test/hash-framing-block/v1";

/// Fixed geometry independent of the complete recipient input's byte length.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 448,
    quotient_chunks: 4,
    main_next: false,
};

/// Selects the block crossing network, suite and complete public-key part boundaries.
fn air() -> BlockAir {
    BlockAir::new(b"houseki/v1/recipient/kem-key", &[64, 4, 1568], 2)
}

/// Assigns public fixture bytes into the protected trace owner.
fn trace() -> Trace {
    let air = air();
    let parts: [&[Goldilocks]; 3] = [
        &[Goldilocks::from_u8(17); 64],
        &[Goldilocks::ONE; 4],
        &[Goldilocks::from_u8(31); 1568],
    ];
    let mut trace = Trace::new(512, LAYOUT.width, 512 * LAYOUT.width).unwrap();
    for row in trace.values_mut().as_chunks_mut::<448>().0 {
        air.assign_row(&parts, row).unwrap();
    }

    trace
}

/// Round trips a real block proof through the unchanged production codec.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff000c),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x6d; 64],
    };

    gadget_proof::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &air(),
            public,
            identity: &identity,
            layout: LAYOUT,
        },
        trace,
    )
}

/// Real proof acceptance and rejection after coordinated downstream witness changes.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier, gadgets::assign_byte};
    use p3_air::{
        BaseAir,
        symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints},
    };
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// Checks all range, fixed-byte, packing and public-output equations against the codec layout.
    #[test]
    fn gadgets_framing_block_geometry_matches_constraints() {
        let air = air();
        let layout = AirLayout::from_air(&air);

        assert_eq!(air.width(), LAYOUT.width);
        assert_eq!(get_symbolic_constraints(&air, layout).len(), 471);
        assert_eq!(get_max_constraint_degree(&air, layout, 512), 2);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&air, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// A real fixed-width block proof binds every packed output word.
    #[test]
    fn gadgets_framing_block_proof_binds_all_words() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let trace = trace();
        let public = trace.values()[441..448].to_vec();
        let proof = prove(&lease, trace, &public).unwrap();

        verifier::verify(&lease, PREFIX, &air(), &proof, &public).unwrap();

        for index in 0..7 {
            let mut changed = public.clone();
            changed[index] += Goldilocks::ONE;

            assert!(verifier::verify(&lease, PREFIX, &air(), &proof, &changed).is_err());
        }
    }

    /// Corrected packing cannot conceal forged metadata or an out-of-range private byte.
    #[test]
    fn gadgets_framing_block_recomputed_forgeries_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        for metadata in [true, false] {
            let mut forged = trace();
            for row in forged.values_mut().as_chunks_mut::<448>().0 {
                if metadata {
                    row[16] += Goldilocks::ONE;
                    let byte = row[16];
                    assign_byte(&byte, (&mut row[177..185]).try_into().unwrap()).unwrap();
                    row[443] += Goldilocks::from_u32(1 << 16);
                } else {
                    row[0] = Goldilocks::from_u16(256);
                    row[49..57].fill(Goldilocks::ZERO);
                    row[56] = Goldilocks::TWO;
                    row[441] += Goldilocks::from_u16(256 - 17);
                }
            }

            let public = forged.values()[441..448].to_vec();
            let result = prove(&lease, forged, &public);

            #[cfg(debug_assertions)]
            assert!(matches!(result, Err(BackendError::ProvingFailed)));

            #[cfg(not(debug_assertions))]
            {
                let proof = result.expect("release prover must reach cryptographic verification");
                assert!(matches!(
                    verifier::verify(&lease, PREFIX, &air(), &proof, &public),
                    Err(BackendError::InvalidProof)
                ));
            }
        }
    }
}
