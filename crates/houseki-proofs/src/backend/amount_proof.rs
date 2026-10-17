//! Real proof checks for the native amount cap and separately selected note positivity.

use super::{
    BackendError, codec, config::BackendProof, gadget_proof, prover::Request, trace::Trace,
};
use crate::{
    gadgets::AmountAir,
    profile::{ExpectedIdentity, Relation},
    runtime::Admission,
};
use houseki_types::ProofProfileId;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Original trace geometry shared by the two compile-time test policies.
const LAYOUT: codec::Layout = codec::Layout {
    log_rows: 9,
    width: AmountAir::<true>::WIDTH,
    quotient_chunks: 4,
    main_next: false,
};

/// Distinguishes the trusted test policies in their synthetic transcripts.
fn prefix<const POSITIVE: bool>() -> &'static [u8] {
    if POSITIVE {
        b"houseki/test/note-amount/v1"
    } else {
        b"houseki/test/fee-amount/v1"
    }
}

/// Assigns an ordinary public amount fixture directly into protected trace storage.
fn trace<const POSITIVE: bool>(value: u128) -> Trace {
    let amount = value.to_le_bytes().map(Goldilocks::from_u8);
    let mut trace = Trace::new(512, 305, 512 * 305).unwrap();
    for row in trace.values_mut().as_chunks_mut::<305>().0 {
        AmountAir::<POSITIVE>::assign_row(&amount, row).unwrap();
    }

    trace
}

/// Proves and decodes under the explicitly selected test policy without production admission.
fn prove<const POSITIVE: bool>(
    admission: &Admission<'_>,
    trace: Trace,
    public: &[Goldilocks],
) -> Result<BackendProof, BackendError> {
    let identity = ExpectedIdentity {
        profile: ProofProfileId::new(0xffff0006),
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: [if POSITIVE { 0x66 } else { 0x67 }; 64],
    };
    gadget_proof::prove(
        admission,
        Request {
            prefix: prefix::<POSITIVE>(),
            air: &AmountAir::<POSITIVE>,
            public,
            identity: &identity,
            layout: LAYOUT,
        },
        trace,
    )
}

/// Native boundary acceptance and cryptographic rejection independent of honest construction.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRuntime, backend::verifier};
    use houseki_types::Amount;
    use p3_air::symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints};
    use p3_field::PrimeField64;
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// Both policies retain the same quadratic budget and exact test codec geometry.
    #[test]
    fn gadgets_amount_geometry_matches_constraints() {
        check_geometry::<true>();
        check_geometry::<false>();
    }

    /// Counts actual symbolic constraints for one selected amount policy.
    fn check_geometry<const POSITIVE: bool>() {
        let air = AmountAir::<POSITIVE>;
        let layout = AirLayout::from_air(&air);

        assert_eq!(get_symbolic_constraints(&air, layout).len(), 338);
        assert_eq!(get_max_constraint_degree(&air, layout, 512), 2);
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&air, layout, 512, 1) + 1),
            LAYOUT.quotient_chunks
        );
    }

    /// The exact note cap and a zero fee both produce verifiable, byte-bound proofs.
    #[test]
    fn gadgets_amount_proofs_accept_cap_and_zero_fee() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        check_valid::<true>(&lease, Amount::MAX_ATOMS);
        check_valid::<false>(&lease, 0);
    }

    /// Checks a valid proof and rejects a changed high public amount byte.
    fn check_valid<const POSITIVE: bool>(admission: &Admission<'_>, value: u128) {
        let public = value.to_le_bytes().map(Goldilocks::from_u8);
        let proof = prove::<POSITIVE>(admission, trace::<POSITIVE>(value), &public).unwrap();

        verifier::verify(
            admission,
            prefix::<POSITIVE>(),
            &AmountAir::<POSITIVE>,
            &proof,
            &public,
        )
        .unwrap();

        let mut changed = public;
        changed[15] += Goldilocks::ONE;

        assert!(
            verifier::verify(
                admission,
                prefix::<POSITIVE>(),
                &AmountAir::<POSITIVE>,
                &proof,
                &changed
            )
            .is_err()
        );
    }

    /// A zero amount built with the fee assigner cannot pass the positive note relation.
    #[test]
    fn gadgets_amount_zero_note_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();

        reject::<true>(&lease, trace::<false>(0));
    }

    /// Valid byte ranges cannot disguise an above-cap value through a wrapping remainder.
    #[test]
    fn gadgets_amount_above_cap_cannot_verify() {
        let runtime = ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let mut forged = trace::<false>(0);
        for row in forged.values_mut().as_chunks_mut::<305>().0 {
            for (slot, value) in [Amount::MAX_ATOMS + 1, u128::MAX].iter().enumerate() {
                for (index, byte) in value.to_le_bytes().iter().enumerate() {
                    row[slot * 16 + index] = Goldilocks::from_u8(*byte);
                    for bit in 0..8 {
                        row[32 + slot * 128 + index * 8 + bit] =
                            Goldilocks::from_bool(byte & (1 << bit) != 0);
                    }
                }
            }

            let mut carry = 0_u16;
            for index in 0..16 {
                carry = (row[index].as_canonical_u64() as u16
                    + row[16 + index].as_canonical_u64() as u16
                    + carry)
                    >> 8;
                row[288 + index] = Goldilocks::from_u16(carry);
            }
        }

        reject::<false>(&lease, forged);
    }

    /// Requires successful malformed proof construction before release verifier rejection.
    fn reject<const POSITIVE: bool>(admission: &Admission<'_>, trace: Trace) {
        let public = trace.values()[..16].to_vec();
        let result = prove::<POSITIVE>(admission, trace, &public);

        #[cfg(debug_assertions)]
        assert!(matches!(result, Err(BackendError::ProvingFailed)));

        #[cfg(not(debug_assertions))]
        {
            let proof = result.expect("release prover must reach cryptographic verification");
            assert!(matches!(
                verifier::verify(
                    admission,
                    prefix::<POSITIVE>(),
                    &AmountAir::<POSITIVE>,
                    &proof,
                    &public
                ),
                Err(BackendError::InvalidProof)
            ));
        }
    }
}
