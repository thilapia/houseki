//! Native private owners, occupied paths and authenticated encrypted payment outputs.

use super::owner::Owner;
use houseki_crypto::{CryptoSuite, PaymentEncryptionCore};
use houseki_notes::{
    NoteBlinding, NoteFormat, NoteOpening, SpendWitness, derive_nullifier, encrypt_payment_output,
    payment_encryption_core,
};
use houseki_proofs::EXPERIMENTAL_PAYMENT_PROFILE;
use houseki_state::{NoteMembershipWitness, NoteTree};
use houseki_types::{
    Amount, CheckpointSequence, FeeScheduleId, NetworkId, NoteTreeAnchor, PaymentBody,
    PaymentCountLimits, PaymentInputs, PaymentOutputs, ProtocolVersion, TransactionContext,
    ValidityCheckpointRange,
};
use std::error::Error;

/// Original native owners for a complete demonstration payment.
pub(super) struct Fixture {
    /// Sender of the input notes and recipient of any change.
    pub(super) sender: Owner,

    /// Independent receiving participant.
    pub(super) receiver: Owner,

    /// Original private input openings in body order.
    inputs: Vec<NoteOpening>,

    /// Occupied paths under the shared original anchor.
    paths: Vec<NoteMembershipWitness>,

    /// Original output openings, with one owner reused for repeated commitments.
    outputs: Vec<NoteOpening>,

    /// Whether each output refers to the same opening and receiving participant.
    repeated: bool,

    /// Complete encrypted public payment.
    pub(super) body: PaymentBody,

    /// Independently supplied original occupied anchor.
    pub(super) anchor: NoteTreeAnchor,

    /// Synthetic local tree for append and subsequent spending.
    pub(super) tree: NoteTree,
}

impl Fixture {
    /// Funds every output occurrence and one separate fee with fresh local notes.
    pub(super) fn new(
        inputs: usize,
        outputs: usize,
        repeated: bool,
    ) -> Result<Self, Box<dyn Error>> {
        if !(1..=4).contains(&inputs) || !(1..=2).contains(&outputs) || (repeated && outputs != 2) {
            return Err(
                "expected 1..4 inputs and 1..2 outputs, with two outputs for repeats".into(),
            );
        }

        let network = NetworkId::from_bytes([7; 64]);
        let sender = Owner::new(network)?;
        let receiver = Owner::new(network)?;
        let inputs: Vec<_> = (0..inputs)
            .map(|_| opening(&sender, 100))
            .collect::<Result<_, _>>()?;
        let mut tree = NoteTree::new(network)?;
        let positions = inputs
            .iter()
            .map(|note| Ok(tree.append(note.commitment()?)?))
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let paths = positions
            .iter()
            .map(|position| tree.witness(position))
            .collect::<Result<_, _>>()?;
        let markers = inputs
            .iter()
            .zip(&positions)
            .map(|(note, position)| derive_nullifier(note, &sender.nullifier, position))
            .collect::<Result<_, _>>()?;
        let anchor = tree.anchor();
        let fee = if repeated { 2 } else { 1 };
        let total = inputs.len() as u128 * 100 - fee;
        let openings = if repeated {
            vec![opening(&receiver, total / 2)?]
        } else if outputs == 1 {
            vec![opening(&receiver, total)?]
        } else {
            vec![
                opening(&receiver, total / 2)?,
                opening(&sender, total - total / 2)?,
            ]
        };
        let output_pairs: Vec<_> = (0..outputs)
            .map(|index| {
                if index == 0 || repeated {
                    (&receiver, &openings[0])
                } else {
                    (&sender, &openings[1])
                }
            })
            .collect();
        let context = TransactionContext::new(
            network,
            ProtocolVersion::new(1),
            EXPERIMENTAL_PAYMENT_PROFILE,
            FeeScheduleId::new(4),
            ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))?,
        );
        let body = encrypted_body(
            context,
            PaymentInputs::new(anchor.root(), markers, limits())?,
            &output_pairs,
            fee,
        )?;

        Ok(Self {
            sender,
            receiver,
            inputs,
            paths,
            outputs: openings,
            repeated,
            body,
            anchor,
            tree,
        })
    }

    /// Borrows all original inputs without copying any private owner.
    pub(super) fn spends(&self) -> Vec<SpendWitness<'_>> {
        self.inputs
            .iter()
            .zip(&self.paths)
            .map(|(note, path)| {
                SpendWitness::new(note, &self.sender.spending, &self.sender.nullifier, path)
            })
            .collect()
    }

    /// Borrows each output occurrence in exactly the body order.
    pub(super) fn outputs(&self) -> Vec<&NoteOpening> {
        (0..self.body.outputs().output_count())
            .map(|index| &self.outputs[if self.repeated { 0 } else { index }])
            .collect()
    }

    /// Returns the independently retained delivery owner for a selected output.
    pub(super) fn output_owner(&self, index: usize) -> &Owner {
        if index == 0 || self.repeated {
            &self.receiver
        } else {
            &self.sender
        }
    }
}

/// Returns the fixed demonstration count bounds independently of supplied proof bytes.
pub(super) fn limits() -> PaymentCountLimits {
    PaymentCountLimits::new(4, 2).expect("nonzero fixed count bounds")
}

/// Creates a fresh ordinary note for one independently retained recipient.
pub(super) fn opening(owner: &Owner, amount: u128) -> Result<NoteOpening, Box<dyn Error>> {
    Ok(NoteOpening::new(
        NoteFormat::V1,
        &owner.recipient,
        Amount::from_atoms(amount)?,
        NoteBlinding::generate()?,
    )?)
}

/// Seals every actual output and compares the reconstructed encryption core before authorization.
pub(super) fn encrypted_body(
    context: TransactionContext,
    inputs: PaymentInputs,
    outputs: &[(&Owner, &NoteOpening)],
    fee: u128,
) -> Result<PaymentBody, Box<dyn Error>> {
    let commitments = outputs
        .iter()
        .map(|(_, note)| Ok((note.commitment()?, CryptoSuite::V1)))
        .collect::<Result<_, Box<dyn Error>>>()?;
    let core = PaymentEncryptionCore::new(
        context,
        inputs,
        commitments,
        Amount::from_atoms(fee)?,
        limits(),
    )?;
    let encrypted = outputs
        .iter()
        .enumerate()
        .map(|(index, (owner, note))| {
            encrypt_payment_output(&core, index as u64, &owner.recipient, note, 4096)
        })
        .collect::<Result<_, _>>()?;
    let body = PaymentBody::new(
        context,
        core.inputs().clone(),
        PaymentOutputs::new(encrypted, limits())?,
        core.public_fee(),
        limits(),
    )?;
    let projected = payment_encryption_core(&body, limits(), 4096)?;
    assert_eq!(projected, core);
    assert_eq!(projected.digest()?, core.digest()?);

    Ok(body)
}

/// Native authentication and exact occurrence conservation independent of proof execution.
#[cfg(test)]
mod tests {
    use super::*;
    use houseki_notes::{check_payment, recover_payment_output};

    /// Every supported shape uses authentic encryption and remains natively spendable.
    #[test]
    fn payment_native_delivery_all_shapes() {
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let fixture = Fixture::new(inputs, outputs, false).unwrap();
                check_payment(
                    &fixture.body,
                    &fixture.anchor,
                    &fixture.spends(),
                    &fixture.outputs(),
                    limits(),
                )
                .unwrap();
                for (index, expected) in fixture.outputs().iter().enumerate() {
                    let owner = fixture.output_owner(index);
                    let recovered = recover_payment_output(
                        &fixture.body,
                        index as u64,
                        &owner.recipient,
                        &owner.decryption,
                        limits(),
                        4096,
                    )
                    .unwrap();
                    assert_eq!(recovered.amount(), expected.amount());
                    assert_eq!(
                        recovered.commitment().unwrap(),
                        expected.commitment().unwrap()
                    );
                }
            }
        }
    }
}
