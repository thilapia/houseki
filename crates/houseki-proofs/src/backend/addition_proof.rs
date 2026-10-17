//! Real proof checks for exact integer sums, modular aliases and final carry rejection.

use super::{
    BackendError, codec, config::BackendProof, gadget_proof, prover::Request, trace::Trace,
};
use crate::{
    gadgets::AdditionAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Domain reserved for the isolated addition relation without production admission.
const PREFIX: &[u8] = b"houseki/test/addition/v1";

/// Original geometry of the shared addition relation under the hiding backend.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: AdditionAir::WIDTH,
    quotient_chunks: 4,
    main_next: false,
};

/// Writes native public integer fixtures directly into protected prover storage.
fn trace(left: u128, right: u128) -> Trace {
    let operands = [left, right].map(|word| word.to_le_bytes().map(Goldilocks::from_u8));
    let mut trace = Trace::new(512, AdditionAir::WIDTH, 512 * AdditionAir::WIDTH).unwrap();
    for row in trace
        .values_mut()
        .as_chunks_mut::<{ AdditionAir::WIDTH }>()
        .0
    {
        AdditionAir::assign_row([&operands[0], &operands[1]], row).unwrap();
    }

    trace
}

/// Proves and decodes under this isolated relation's explicit test identity.
fn prove(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff0006),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [0x65; 64],
    };
    gadget_proof::prove(
        admission,
        Request {
            prefix: PREFIX,
            air: &AdditionAir,
            public,
            identity: &identity,
            layout: LAYOUT,
        },
        trace,
    )
}

/// Exact integer behavior through protected proving, canonical decoding and real verification.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use houseki_types::Amount;
    use p3_air::symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints};
    use p3_field::{Field, PrimeField64};
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// Accounts for all byte ranges, every carry and the final zero carry.
    #[test]
    fn gadgets_addition_geometry_matches_constraints() {
        let layout = AirLayout::from_air(&AdditionAir);

        assert_eq!(get_symbolic_constraints(&AdditionAir, layout).len(), 513);
        assert_eq!(get_max_constraint_degree(&AdditionAir, layout, 512), 2);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&AdditionAir, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// Real proofs retain totals above the field modulus and above the individual amount cap.
    #[test]
    fn gadgets_addition_proofs_preserve_exact_totals() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        for (left, right) in [
            (u128::from(Goldilocks::ORDER_U64) - 1, 1),
            (2 * Amount::MAX_ATOMS, Amount::MAX_ATOMS),
        ] {
            let trace = trace(left, right);
            let public = trace.values()[..48].to_vec();
            let proof = prove(&lease, trace, &public).unwrap();

            verifier::verify(&lease, PREFIX, &AdditionAir, &proof, &public).unwrap();

            let mut changed = public;
            changed[47] += Goldilocks::ONE;

            assert!(verifier::verify(&lease, PREFIX, &AdditionAir, &proof, &changed).is_err());
        }
    }

    /// Algebraically matching modular carries cannot substitute for Boolean integer carries.
    #[test]
    fn gadgets_addition_modular_alias_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let mut forged = trace(0, 0);
        for row in forged
            .values_mut()
            .as_chunks_mut::<{ AdditionAir::WIDTH }>()
            .0
        {
            let inverse_radix = Goldilocks::from_u16(256).inverse();
            let mut carry = Goldilocks::ZERO;
            for (index, byte) in u128::from(Goldilocks::ORDER_U64)
                .to_le_bytes()
                .iter()
                .enumerate()
            {
                row[index] = Goldilocks::from_u8(*byte);
                for bit in 0..8 {
                    row[48 + 8 * index + bit] = Goldilocks::from_bool(byte & (1 << bit) != 0);
                }

                carry = (row[index] + carry) * inverse_radix;
                row[432 + index] = carry;
            }
        }

        reject(&lease, forged);
    }

    /// A correct carry chain that overflows the integer capacity is rejected cryptographically.
    #[test]
    fn gadgets_addition_final_overflow_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let mut forged = trace(0, 0);
        for row in forged
            .values_mut()
            .as_chunks_mut::<{ AdditionAir::WIDTH }>()
            .0
        {
            row[..16].fill(Goldilocks::from_u8(255));
            row[48..176].fill(Goldilocks::ONE);
            row[16] = Goldilocks::ONE;
            row[176] = Goldilocks::ONE;
            row[432..].fill(Goldilocks::ONE);
        }

        reject(&lease, forged);
    }

    /// Requires successful malformed proof construction followed by verifier rejection in release.
    fn reject(admission: &Admission<'_>, trace: Trace) {
        let public = trace.values()[..48].to_vec();
        let result = prove(admission, trace, &public);

        #[cfg(debug_assertions)]
        assert!(matches!(result, Err(BackendError::ProvingFailed)));

        #[cfg(not(debug_assertions))]
        {
            let proof = result.expect("release prover must reach cryptographic verification");
            assert!(matches!(
                verifier::verify(admission, PREFIX, &AdditionAir, &proof, &public),
                Err(BackendError::InvalidProof)
            ));
        }
    }
}
