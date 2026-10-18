//! Synthetic native owners, real occupied paths and opaque public payment bodies for tests.

use houseki_crypto::{CryptoSuite, MlKem1024DecapsulationKey, NullifierKey, SpendingKey};
use houseki_notes::{
    NoteBlinding, NoteFormat, NoteOpening, NoteRecipient, SpendWitness, derive_nullifier,
};
use houseki_state::{NoteMembershipWitness, NoteTree};
use houseki_types::*;

/// Owns each native secret while tests borrow witnesses through the public facade.
pub(super) struct PaymentFixture {
    /// Shared deterministic spending authority used only by fixtures.
    spending: SpendingKey,

    /// Independent deterministic nullifier secret used only by fixtures.
    nullifier: NullifierKey,

    /// Every original input opening in body order.
    inputs: Vec<NoteOpening>,

    /// Original paths after all fixture inputs were appended.
    paths: Vec<NoteMembershipWitness>,

    /// Every output opening in body order.
    openings: Vec<NoteOpening>,

    /// Reuses the first private owner at every distinct input position and output occurrence.
    repeated: bool,

    /// Canonical effects with intentionally opaque envelopes.
    pub(super) body: PaymentBody,

    /// Actual occupied anchor for all input paths.
    pub(super) anchor: NoteTreeAnchor,
}

impl PaymentFixture {
    /// Funds each output occurrence and exactly one atom of public fee under real membership.
    pub(super) fn new(inputs: usize, outputs: usize) -> Self {
        let amount = inputs as u128 * 11 - 1;
        let outputs: Vec<_> = (0..outputs)
            .map(|index| {
                if index + 1 == outputs {
                    amount - (outputs - 1) as u128
                } else {
                    1
                }
            })
            .collect();
        Self::with_amounts(&vec![11; inputs], &outputs, 1, false)
    }

    /// Builds arbitrary positive note amounts, fees and repeated owners for independent relation checks.
    pub(super) fn with_amounts(
        inputs: &[u128],
        outputs: &[u128],
        fee: u128,
        repeated: bool,
    ) -> Self {
        let network = NetworkId::from_bytes([7; 64]);
        let spending = SpendingKey::from_bytes(&[17; 32]);
        let nullifier = NullifierKey::from_bytes(&[29; 32]);
        let kem = MlKem1024DecapsulationKey::from_seed(&[11; 64]);
        let recipient = NoteRecipient::validate(
            &RecipientDescriptor::new(
                AddressContext::new(network, AddressFormatVersion::new(1), CryptoSuite::V1.id()),
                spending.ownership_commitment(network, &nullifier).unwrap(),
                kem.encapsulation_key().to_encoded(),
            ),
            network,
        )
        .unwrap();
        let opening = |amount| {
            NoteOpening::new(
                NoteFormat::V1,
                &recipient,
                Amount::from_atoms(amount).unwrap(),
                NoteBlinding::generate().unwrap(),
            )
            .unwrap()
        };
        let input_openings: Vec<_> = inputs.iter().copied().map(opening).collect();
        let openings: Vec<_> = outputs.iter().copied().map(opening).collect();
        let mut tree = NoteTree::new(network).unwrap();
        let positions: Vec<_> = input_openings
            .iter()
            .map(|opening| {
                tree.append(if repeated {
                    input_openings[0].commitment().unwrap()
                } else {
                    opening.commitment().unwrap()
                })
                .unwrap()
            })
            .collect();
        let paths = positions
            .iter()
            .map(|position| tree.witness(position).unwrap())
            .collect();
        let markers = input_openings
            .iter()
            .zip(&positions)
            .map(|(opening, position)| {
                derive_nullifier(
                    if repeated {
                        &input_openings[0]
                    } else {
                        opening
                    },
                    &nullifier,
                    position,
                )
                .unwrap()
            })
            .collect();
        let anchor = tree.anchor();
        let counts = PaymentCountLimits::new(4, 2).unwrap();
        let outputs = openings
            .iter()
            .map(|opening| {
                NoteOutput::new(
                    if repeated {
                        openings[0].commitment().unwrap()
                    } else {
                        opening.commitment().unwrap()
                    },
                    EncryptedNoteEnvelope::new(
                        EncodedMlKem1024Ciphertext::from_bytes([21; 1568]),
                        vec![31; 3],
                        3,
                    )
                    .unwrap(),
                )
            })
            .collect();
        let context = TransactionContext::new(
            network,
            ProtocolVersion::new(1),
            crate::profile::payment::EXPERIMENTAL_PAYMENT_PROFILE,
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))
                .unwrap(),
        );
        let body = PaymentBody::new(
            context,
            PaymentInputs::new(anchor.root(), markers, counts).unwrap(),
            PaymentOutputs::new(outputs, counts).unwrap(),
            Amount::from_atoms(fee).unwrap(),
            counts,
        )
        .unwrap();

        Self {
            repeated,
            spending,
            nullifier,
            inputs: input_openings,
            paths,
            openings,
            body,
            anchor,
        }
    }

    /// Borrows every original input owner and path without cloning protected state.
    pub(super) fn spends(&self) -> Vec<SpendWitness<'_>> {
        self.inputs
            .iter()
            .zip(&self.paths)
            .map(|(opening, path)| {
                SpendWitness::new(
                    if self.repeated {
                        &self.inputs[0]
                    } else {
                        opening
                    },
                    &self.spending,
                    &self.nullifier,
                    path,
                )
            })
            .collect()
    }

    /// Borrows the actual output openings in their public body order.
    pub(super) fn outputs(&self) -> Vec<&NoteOpening> {
        self.openings
            .iter()
            .map(|opening| {
                if self.repeated {
                    &self.openings[0]
                } else {
                    opening
                }
            })
            .collect()
    }
}
