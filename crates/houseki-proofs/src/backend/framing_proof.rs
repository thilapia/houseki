//! Real proofs for fixed transcript framing, byte packing and mandatory sponge padding.

use super::{
    BackendError, codec, config::BackendProof, gadget_proof, prover::Request, trace::Trace,
};
use crate::{
    gadgets::FramingAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_air::BaseAir;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Synthetic framing identity distinct from every production statement.
const PREFIX: &[u8] = b"houseki/test/hash-framing/v1";

/// Geometry for 48 input bytes, fourteen packed words and a full padding block.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: 453,
    quotient_chunks: 4,
    main_next: false,
};

/// Selects the registered native domain and an exact-rate public test shape.
fn air() -> FramingAir {
    FramingAir::new(b"houseki/v1/recipient/kem-key", &[48])
}

/// Assigns public byte fixtures into protected trace storage.
fn trace() -> Trace {
    let air = air();
    let mut trace = Trace::new(512, LAYOUT.width, 512 * LAYOUT.width).unwrap();
    for row in trace.values_mut().as_chunks_mut::<453>().0 {
        air.assign_row(&[Goldilocks::from_u8(0xa3); 48], row)
            .unwrap();
    }

    trace
}

/// Encodes and decodes a real proof under a synthetic identity without production admission.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff0007),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x68; 64],
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

/// Complete padded input acceptance and verifier rejection of independently forged cells.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use p3_air::symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints};
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// Measures the actual relation including public links against the bounded test codec.
    #[test]
    fn gadgets_framing_geometry_matches_constraints() {
        let air = air();
        let layout = AirLayout::from_air(&air);

        assert_eq!(air.width(), LAYOUT.width);
        assert_eq!(get_symbolic_constraints(&air, layout).len(), 474);
        assert_eq!(get_max_constraint_degree(&air, layout, 512), 2);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&air, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// Exact-rate input retains a full padding block and binds all words into a real proof.
    #[test]
    fn gadgets_framing_proofs_bind_complete_padded_input() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let trace = trace();
        let public = trace.values()[432..453].to_vec();
        let proof = prove(&lease, trace, &public).unwrap();

        verifier::verify(&lease, PREFIX, &air(), &proof, &public).unwrap();

        for index in [0, 13, 14, 20] {
            let mut changed = public.clone();
            changed[index] += Goldilocks::ONE;

            assert!(verifier::verify(&lease, PREFIX, &air(), &proof, &changed).is_err());
        }
    }

    /// Forged frame lengths, domains, counts, part lengths and padding cannot verify.
    #[test]
    fn gadgets_framing_forged_metadata_and_padding_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        for (word, delta) in [
            (0, 1),
            (1, 1 << 8),
            (1, 1 << 24),
            (5, 1 << 24),
            (6, 1),
            (14, 1),
            (20, 1),
        ] {
            let mut forged = trace();
            for row in forged.values_mut().as_chunks_mut::<453>().0 {
                row[432 + word] += Goldilocks::from_u32(delta);
            }

            reject(&lease, forged);
        }
    }

    /// A non-Boolean bit cannot disguise an out-of-range byte even with corrected packed words.
    #[test]
    fn gadgets_framing_non_byte_input_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let mut forged = trace();
        for row in forged.values_mut().as_chunks_mut::<453>().0 {
            row[0] = Goldilocks::from_u16(256);
            row[48..56].fill(Goldilocks::ZERO);
            row[55] = Goldilocks::TWO;
            row[432 + 7] += Goldilocks::from_u32((256 - 0xa3) * 256);
        }

        reject(&lease, forged);
    }

    /// Requires release proof construction to succeed before cryptographic rejection.
    fn reject(admission: &Admission<'_>, trace: Trace) {
        let public = trace.values()[432..453].to_vec();
        let result = prove(admission, trace, &public);

        #[cfg(debug_assertions)]
        assert!(matches!(result, Err(BackendError::ProvingFailed)));

        #[cfg(not(debug_assertions))]
        {
            let proof = result.expect("release prover must reach cryptographic verification");
            assert!(matches!(
                verifier::verify(admission, PREFIX, &air(), &proof, &public),
                Err(BackendError::InvalidProof)
            ));
        }
    }
}
