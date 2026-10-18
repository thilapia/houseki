//! Shared native owner conversion into guarded byte valued field inputs.

mod opening;
mod spend;

pub(crate) use opening::OpeningFields;
#[cfg_attr(
    not(test),
    expect(unused_imports, reason = "reserved for private family dispatch")
)]
pub(crate) use spend::SpendFields;

use super::trace::Trace;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Writes one canonical byte per field element without integer reduction or temporary vectors.
fn write(destination: &mut [Goldilocks], bytes: &[u8]) {
    assert_eq!(destination.len(), bytes.len(), "fixed witness layout");

    for (cell, byte) in destination.iter_mut().zip(bytes) {
        *cell = Goldilocks::from_u8(*byte);
    }
}

/// Borrows a statically selected range from a fixed protected layout.
fn part<const N: usize>(trace: &Trace, offset: usize) -> &[Goldilocks; N] {
    trace.values()[offset..offset + N]
        .try_into()
        .expect("fixed witness layout")
}

/// Real native fixtures and field conversion properties.
#[cfg(test)]
mod tests {
    use super::*;
    use houseki_crypto::{CryptoSuite, NullifierKey, SpendingKey, note_membership_root};
    use houseki_notes::NoteOpening;
    use houseki_notes::{NoteBlinding, NoteFormat, NoteRecipient, SpendWitness};
    use houseki_state::NoteMembershipWitness;
    use houseki_types::{
        AddressContext, AddressFormatVersion, Amount, EncodedMlKem1024PublicKey, NetworkId,
        NoteCount, NotePosition, NoteTreeAnchor, RecipientDescriptor,
    };
    use p3_field::PrimeField64;
    use zeroize::Zeroizing;

    /// Makes a checked recipient tied to the actual deterministic native key owners.
    fn opening(atoms: u128, spending: &SpendingKey, nullifier: &NullifierKey) -> NoteOpening {
        let network = NetworkId::from_bytes([7; 64]);
        let mut key = [0; 1568];
        for (index, pair) in key[..1536].as_chunks_mut::<3>().0.iter_mut().enumerate() {
            let first = (index * 19 % 3329) as u16;
            let second = (3328 - index * 7 % 3329) as u16;
            pair.copy_from_slice(&[
                first as u8,
                ((first >> 8) | (second << 4)) as u8,
                (second >> 4) as u8,
            ]);
        }

        key[1536..].fill(255);

        let descriptor = RecipientDescriptor::new(
            AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
            spending.ownership_commitment(network, nullifier).unwrap(),
            EncodedMlKem1024PublicKey::from_bytes(key),
        );
        let recipient = NoteRecipient::validate(&descriptor, network).unwrap();

        NoteOpening::new(
            NoteFormat::V1,
            &recipient,
            Amount::from_atoms(atoms).unwrap(),
            NoteBlinding::generate().unwrap(),
        )
        .unwrap()
    }

    /// Reconstructs synthetic fixture bytes without reducing or exposing a production owner.
    fn bytes<const N: usize>(fields: &[Goldilocks; N]) -> [u8; N] {
        fields.map(|value| u8::try_from(value.as_canonical_u64()).unwrap())
    }

    /// Preserves both keys, complete recipient encoding and all positive amount boundary bytes.
    #[test]
    fn actual_native_openings_convert_without_field_reduction() {
        let spending = SpendingKey::from_bytes(&[17; 32]);
        let nullifier = NullifierKey::from_bytes(&[29; 32]);

        for amount in [1, 255, 1 << 64, Amount::MAX_ATOMS - 1, Amount::MAX_ATOMS] {
            let opening = opening(amount, &spending, &nullifier);
            let fields = OpeningFields::new(&opening).unwrap();

            assert_eq!(bytes(fields.amount()), amount.to_le_bytes());

            let mut expected_blinding = Zeroizing::new([0; 32]);
            opening.write_proof_blinding(&mut expected_blinding);

            assert_eq!(bytes(fields.blinding()), *expected_blinding);
            assert_eq!(bytes(fields.recipient()), opening.recipient().to_bytes());
            assert_eq!(bytes(fields.version()), 1_u32.to_le_bytes());
            assert_eq!(opening.amount().atoms(), amount);
        }
    }

    /// Actual native owners with varied canonical coefficients satisfy the complete shared relation.
    #[test]
    fn native_openings_satisfy_the_complete_shared_constraints() {
        let spending = SpendingKey::from_bytes(&[17; 32]);
        let nullifier = NullifierKey::from_bytes(&[29; 32]);
        let air = crate::gadgets::OpeningAir::new();
        for amount in [1, 1 << 64, Amount::MAX_ATOMS] {
            let native = opening(amount, &spending, &nullifier);
            let fields = OpeningFields::new(&native).unwrap();
            let mut trace = Trace::new(
                128,
                crate::gadgets::Opening::WIDTH,
                128 * crate::gadgets::Opening::WIDTH,
            )
            .unwrap();
            air.opening
                .assign(fields.input(), trace.values_mut())
                .unwrap();

            let mut public = vec![Goldilocks::from_u8(7); 144];
            public[64..80].copy_from_slice(&amount.to_le_bytes().map(Goldilocks::from_u8));
            public[80..].copy_from_slice(
                &native
                    .commitment()
                    .unwrap()
                    .as_bytes()
                    .map(Goldilocks::from_u8),
            );
            assert!((0..128).all(|phase| air.valid_row(trace.values(), &public, phase)));
        }
    }

    /// Checks all 64 levels and position extremes against real native membership and count binding.
    #[test]
    fn native_paths_preserve_all_levels_and_full_occupied_counts() {
        let spending = SpendingKey::from_bytes(&[17; 32]);
        let nullifier = NullifierKey::from_bytes(&[29; 32]);
        let opening = opening(17, &spending, &nullifier);
        let siblings =
            std::array::from_fn(|level| std::array::from_fn(|byte| (level + byte) as u8));
        let commitment = opening.commitment().unwrap();
        let network = opening.recipient().context().network_id();

        for count in [1, 2, 1 << 32, 1 << 63, u128::from(u64::MAX), 1 << 64] {
            let count = NoteCount::new(count).unwrap();
            let position = NotePosition::new((count.value() - 1) as u64);
            let membership = NoteMembershipWitness::from_parts(&position, &siblings);
            let root =
                note_membership_root(network, count, &commitment, &position, &siblings).unwrap();
            let anchor = NoteTreeAnchor::new(network, count, root);

            membership.verify(&anchor, &commitment).unwrap();

            let witness = SpendWitness::new(&opening, &spending, &nullifier, &membership);
            let marker = houseki_notes::derive_nullifier(&opening, &nullifier, &position).unwrap();
            houseki_notes::check_spend(&anchor, marker, &witness).unwrap();

            let fields = SpendFields::new(&witness).unwrap();

            assert_eq!(bytes(fields.spending_key()), [17; 32]);
            assert_eq!(bytes(fields.nullifier_key()), [29; 32]);
            assert_eq!(bytes(fields.position()), position.value().to_le_bytes());
            assert_eq!(bytes(fields.opening().amount()), 17_u128.to_le_bytes());
            for (level, expected) in siblings.iter().enumerate() {
                assert_eq!(&bytes(fields.sibling(level).unwrap()), expected);
                assert!(std::ptr::eq(
                    fields.sibling(level).unwrap(),
                    &fields.siblings()[level]
                ));
            }

            assert!(fields.sibling(64).is_none());
        }
    }

    /// Borrows original slices for all eight bounded shapes and rejects unsupported counts.
    #[test]
    fn payment_witness_reuses_native_owners_for_every_shape() {
        let spending = SpendingKey::from_bytes(&[17; 32]);
        let nullifier = NullifierKey::from_bytes(&[29; 32]);
        let opening = opening(17, &spending, &nullifier);
        let membership = NoteMembershipWitness::from_parts(&NotePosition::new(0), &[[0; 64]; 64]);
        let inputs = std::array::from_fn::<_, 5, _>(|_| {
            SpendWitness::new(&opening, &spending, &nullifier, &membership)
        });

        let outputs = [&opening; 3];

        for input_count in 0..=5 {
            for output_count in 0..=3 {
                let (result, allocations, _) = crate::test_allocator::measure(|| {
                    crate::PaymentWitness::new(&inputs[..input_count], &outputs[..output_count])
                });

                assert_eq!(allocations, 0);
                if (1..=4).contains(&input_count) && (1..=2).contains(&output_count) {
                    let witness = result.unwrap();
                    assert!(std::ptr::eq(witness.inputs(), &inputs[..input_count]));
                    assert!(std::ptr::eq(witness.outputs(), &outputs[..output_count]));
                    assert_eq!(format!("{witness:#?}"), "PaymentWitness([REDACTED])");
                } else {
                    assert!(result.is_err());
                }
            }
        }
    }

    /// Exercises the guarded native conversion through a real proof of the synthetic square relation.
    #[test]
    fn native_field_conversion_feeds_actual_proving_and_verification() {
        let spending = SpendingKey::from_bytes(&[17; 32]);
        let nullifier = NullifierKey::from_bytes(&[29; 32]);
        let opening = opening(17, &spending, &nullifier);
        let fields = OpeningFields::new(&opening).unwrap();
        let mut trace = Trace::new(512, 1, 512).unwrap();
        trace.values_mut().fill(fields.amount()[0]);

        let runtime = crate::ProofRuntime::new();
        let lease = runtime.acquire().unwrap();
        let public = [Goldilocks::from_u64(289)];

        let proof = super::super::prover::prove(
            &lease,
            b"native conversion",
            &crate::backend::square_air::SquareAir,
            trace,
            &public,
        )
        .unwrap();

        super::super::verifier::verify(
            &lease,
            b"native conversion",
            &crate::backend::square_air::SquareAir,
            &proof,
            &public,
        )
        .unwrap();
    }
}
