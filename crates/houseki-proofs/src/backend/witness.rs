//! Shared native owner conversion into guarded byte-valued field inputs.

use houseki_notes::{NoteOpening, SpendWitness};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

use super::{BackendError, trace::Trace};

/// Protected canonical opening inputs shared by payment and withdrawal trace construction.
///
/// These byte limbs describe native values and do not establish AIR constraints or a proof.
pub(crate) struct OpeningFields {
    /// Version, full recipient, amount and blinding in fixed canonical byte order.
    cells: Trace,
}

impl OpeningFields {
    /// Exact cells for four version bytes, 1704 recipient bytes, 16 amount bytes and 32 blinding bytes.
    const CELLS: usize = 1756;

    /// Converts the original owners into one bounded protected field allocation.
    pub(crate) fn new(opening: &NoteOpening) -> Result<Self, BackendError> {
        let mut cells = Trace::new(1, Self::CELLS, Self::CELLS)?;
        write(
            &mut cells.values_mut()[..4],
            &opening.format().version().value().to_le_bytes(),
        );
        let recipient = Zeroizing::new(opening.recipient().to_bytes());
        write(&mut cells.values_mut()[4..1708], recipient.as_slice());
        let amount = Zeroizing::new(opening.amount().atoms().to_le_bytes());
        write(&mut cells.values_mut()[1708..1724], amount.as_slice());
        let mut blinding = Zeroizing::new([0; 32]);
        opening.write_proof_blinding(&mut blinding);
        write(&mut cells.values_mut()[1724..], blinding.as_slice());
        Ok(Self { cells })
    }

    /// Borrows all version bytes without narrowing the declared identifier.
    pub(crate) fn version(&self) -> &[Goldilocks; 4] {
        part(&self.cells, 0)
    }

    /// Borrows the complete recipient context, ownership and encapsulation key encoding.
    pub(crate) fn recipient(&self) -> &[Goldilocks; 1704] {
        part(&self.cells, 4)
    }

    /// Borrows all sixteen amount limbs, including high bytes above a machine word.
    pub(crate) fn amount(&self) -> &[Goldilocks; 16] {
        part(&self.cells, 1708)
    }

    /// Borrows the private blinding while its field owner remains alive.
    pub(crate) fn blinding(&self) -> &[Goldilocks; 32] {
        part(&self.cells, 1724)
    }
}

/// Protected opening, ownership keys, original position and full membership path for one spend.
pub(crate) struct SpendFields {
    /// Opening representation reused by both relation families.
    opening: OpeningFields,

    /// Two keys, original position and 64 complete siblings in leaf to root order.
    cells: Trace,
}

impl SpendFields {
    /// Exact cells for two 32 byte keys, eight position bytes and 4096 sibling bytes.
    const CELLS: usize = 4168;

    /// Copies only the specified native capabilities into protected byte limbs.
    pub(crate) fn new(witness: &SpendWitness<'_>) -> Result<Self, BackendError> {
        let opening = OpeningFields::new(witness.opening())?;
        let mut cells = Trace::new(1, Self::CELLS, Self::CELLS)?;
        let mut key = Zeroizing::new([0; 32]);
        witness.spending_key().write_proof_bytes(&mut key);
        write(&mut cells.values_mut()[..32], key.as_slice());
        witness.nullifier_key().write_proof_bytes(&mut key);
        write(&mut cells.values_mut()[32..64], key.as_slice());
        let position = Zeroizing::new(
            witness
                .membership()
                .original_position()
                .value()
                .to_le_bytes(),
        );
        write(&mut cells.values_mut()[64..72], position.as_slice());

        let mut sibling = Zeroizing::new([0; 64]);
        for level in 0..64 {
            crate::memory::checkpoint();
            witness
                .membership()
                .write_proof_sibling(level, &mut sibling)
                .map_err(|_| BackendError::InvalidTrace)?;
            write(
                &mut cells.values_mut()[72 + level * 64..136 + level * 64],
                sibling.as_slice(),
            );
        }
        Ok(Self { opening, cells })
    }

    /// Borrows the shared protected opening without copying its amount or recipient.
    pub(crate) fn opening(&self) -> &OpeningFields {
        &self.opening
    }

    /// Borrows all original spending key bytes.
    pub(crate) fn spending_key(&self) -> &[Goldilocks; 32] {
        part(&self.cells, 0)
    }

    /// Borrows all original nullifier key bytes.
    pub(crate) fn nullifier_key(&self) -> &[Goldilocks; 32] {
        part(&self.cells, 32)
    }

    /// Borrows the original position as eight little endian byte limbs.
    pub(crate) fn position(&self) -> &[Goldilocks; 8] {
        part(&self.cells, 64)
    }

    /// Borrows one complete sibling and returns none for every level outside the fixed depth.
    pub(crate) fn sibling(&self, level: usize) -> Option<&[Goldilocks; 64]> {
        if level >= 64 {
            return None;
        }
        Some(part(&self.cells, 72 + level * 64))
    }
}

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
    use houseki_notes::{NoteBlinding, NoteFormat, NoteRecipient, SpendWitness};
    use houseki_state::NoteMembershipWitness;
    use houseki_types::{
        AddressContext, AddressFormatVersion, Amount, EncodedMlKem1024PublicKey, NetworkId,
        NoteCount, NotePosition, NoteTreeAnchor, RecipientDescriptor,
    };
    use p3_field::PrimeField64;

    /// Makes a checked recipient tied to the actual deterministic native key owners.
    fn opening(atoms: u128, spending: &SpendingKey, nullifier: &NullifierKey) -> NoteOpening {
        let network = NetworkId::from_bytes([7; 64]);
        let mut key = [0; 1568];
        key[1536..].fill(91);
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
            }
            assert!(fields.sibling(64).is_none());
        }
    }

    /// Borrows original slices for all four launch shapes and rejects unsupported counts.
    #[test]
    fn payment_witness_reuses_native_owners_for_every_shape() {
        let spending = SpendingKey::from_bytes(&[17; 32]);
        let nullifier = NullifierKey::from_bytes(&[29; 32]);
        let opening = opening(17, &spending, &nullifier);
        let membership = NoteMembershipWitness::from_parts(&NotePosition::new(0), &[[0; 64]; 64]);
        let inputs = std::array::from_fn::<_, 3, _>(|_| {
            SpendWitness::new(&opening, &spending, &nullifier, &membership)
        });
        let outputs = [&opening; 3];
        for input_count in 0..=3 {
            for output_count in 0..=3 {
                let result =
                    crate::PaymentWitness::new(&inputs[..input_count], &outputs[..output_count]);
                if (1..=2).contains(&input_count) && (1..=2).contains(&output_count) {
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
            &super::super::tests::SquareAir,
            trace,
            &public,
        )
        .unwrap();
        super::super::verifier::verify(
            &lease,
            b"native conversion",
            &super::super::tests::SquareAir,
            &proof,
            &public,
        )
        .unwrap();
    }
}
