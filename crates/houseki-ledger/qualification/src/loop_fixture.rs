//! Real value-loop construction with recovery from actual committed context.

use crate::{
    Measurement, PublicFixture, Workload,
    execution::{bootstrap, occurrence, run},
    payment_fixture::{encrypted_body, limits, opening},
    producer::prove_payment_body,
    wallet::Owner,
};
use houseki_crypto::{CryptoSuite, MlDsa87SigningKey, RewardWithdrawalEncryptionCore};
use houseki_notes::{
    SpendWitness, derive_nullifier, encrypt_withdrawal_output, recover_withdrawal_output,
};
use houseki_proofs::{
    CancellationToken, EXPERIMENTAL_PAYMENT_PROFILE, EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE,
    ProofContext, ProofRuntime, prove_reward_withdrawal,
};
use houseki_state::NoteTree;
use houseki_types::{
    Amount, CheckpointSequence, FeeScheduleId, NetworkId, PaymentEnvelope, PaymentInputs,
    ProtocolVersion, RewardWithdrawalBody, RewardWithdrawalEnvelope, TransactionContext,
    ValidityCheckpointRange, WithdrawalNonce,
};
use std::{error::Error, time::Instant};

/// Executes the exact three-step value loop with original recipient secrets kept locally.
pub(crate) fn build(workload: Workload) -> Result<PublicFixture, Box<dyn Error>> {
    let network = NetworkId::from_bytes([7; 64]);
    let sender = Owner::new(network)?;
    let recipient = Owner::new(network)?;
    let a = MlDsa87SigningKey::generate()?;
    let b = MlDsa87SigningKey::generate()?;
    let c = MlDsa87SigningKey::generate()?;
    let notes = [
        opening(&sender, 10)?,
        opening(&sender, 10)?,
        opening(&sender, 80)?,
    ];
    let leaves = notes
        .iter()
        .map(|n| Ok(n.commitment()?))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mapping = if workload == Workload::SharedBeneficiary {
        [0, 0, 0]
    } else {
        [0, 1, 2]
    };
    let m = bootstrap(
        leaves.clone(),
        100,
        &[&a, &b, &c],
        &[0, 0, 0],
        &mapping,
        houseki_ledger::ExecutionPolicy::development()?,
    )?;
    let mut tree = NoteTree::new(network)?;
    let positions = leaves
        .iter()
        .map(|leaf| tree.append(*leaf))
        .collect::<Result<Vec<_>, _>>()?;
    let paths = [tree.witness(&positions[0])?, tree.witness(&positions[1])?];
    let markers = (0..2)
        .map(|i| derive_nullifier(&notes[i], &sender.nullifier, &positions[i]))
        .collect::<Result<Vec<_>, _>>()?;
    let context = TransactionContext::new(
        network,
        ProtocolVersion::new(1),
        EXPERIMENTAL_PAYMENT_PROFILE,
        FeeScheduleId::new(0xffff0001),
        ValidityCheckpointRange::new(CheckpointSequence::new(0), CheckpointSequence::new(100))?,
    );
    let outputs = [opening(&recipient, 8)?, opening(&sender, 8)?];
    let first_body = encrypted_body(
        context,
        PaymentInputs::new(tree.anchor().root(), markers, limits())?,
        &[(&recipient, &outputs[0]), (&sender, &outputs[1])],
        4,
    )?;
    let spends = [
        SpendWitness::new(&notes[0], &sender.spending, &sender.nullifier, &paths[0]),
        SpendWitness::new(&notes[1], &sender.spending, &sender.nullifier, &paths[1]),
    ];
    let mut measurement = Measurement::default();
    let first_proof = prove_payment_body(
        &first_body,
        &tree.anchor(),
        &spends,
        &[&outputs[0], &outputs[1]],
        &mut measurement,
    )?;
    let withdrawal_opening = opening(&recipient, 3)?;
    let withdrawal_context = TransactionContext::new(
        network,
        ProtocolVersion::new(1),
        EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE,
        FeeScheduleId::new(0xffff0001),
        context.validity_checkpoint_range(),
    );
    let core = RewardWithdrawalEncryptionCore::new(
        withdrawal_context,
        m.accounts[0].0,
        a.verification_key().to_encoded(),
        WithdrawalNonce::new(0),
        Amount::from_atoms(3)?,
        Amount::from_atoms(1)?,
        (withdrawal_opening.commitment()?, CryptoSuite::V1),
    )?;
    let output = encrypt_withdrawal_output(&core, &recipient.recipient, &withdrawal_opening, 4096)?;
    let withdrawal_body = RewardWithdrawalBody::new(
        withdrawal_context,
        m.accounts[0].0,
        a.verification_key().to_encoded(),
        WithdrawalNonce::new(0),
        Amount::from_atoms(3)?,
        Amount::from_atoms(1)?,
        output,
    )?;
    let proof_context = ProofContext::new(withdrawal_context)?;
    let signature = a.sign_reward_withdrawal(&withdrawal_body, proof_context.body_limits())?;
    let started = Instant::now();
    let withdrawal_proof = prove_reward_withdrawal(
        &ProofRuntime::new(),
        &withdrawal_body,
        &withdrawal_opening,
        &proof_context,
        &CancellationToken::new(),
    )?;
    measurement.proving += started.elapsed();
    let first = occurrence(
        PaymentEnvelope::new(first_body, first_proof).into(),
        0,
        11,
        0,
    );
    let withdrawal = RewardWithdrawalEnvelope::new(withdrawal_body, withdrawal_proof, signature);
    let first_unit = if workload == Workload::FailedEarlyCopy {
        vec![
            occurrence(withdrawal.clone().into(), 1, 12, 0),
            first,
            occurrence(withdrawal.clone().into(), 1, 12, 1),
            occurrence(withdrawal.into(), 1, 12, 2),
        ]
    } else {
        vec![first, occurrence(withdrawal.into(), 1, 12, 0)]
    };
    // A provisional complete one-unit fixture supplies committed recovery context before the
    // final finite two-unit stream can bind the freshly generated subsequent randomized proof.
    let preliminary = run(m.clone(), vec![first_unit.clone()], Measurement::default())?;
    let (next_envelope, withdrawal_position, expected_marker) = {
        let checkpoint = &preliminary.checkpoints[0];
        let accepted = checkpoint
            .accepted_outputs()
            .find(|o| matches!(o.body(), houseki_ledger::OutputBody::RewardWithdrawal(_)))
            .ok_or("withdrawal not accepted")?;
        let houseki_ledger::OutputBody::RewardWithdrawal(body) = accepted.body() else {
            unreachable!()
        };
        let recovered =
            recover_withdrawal_output(body, &recipient.recipient, &recipient.decryption, 4096)?;
        assert_eq!(recovered.amount().atoms(), 3);
        let mut actual_tree = NoteTree::new(network)?;
        for &leaf in checkpoint.state().leaves() {
            actual_tree.append(leaf)?;
        }
        let path = actual_tree.witness(&accepted.position())?;
        let marker = derive_nullifier(&recovered, &recipient.nullifier, &accepted.position())?;
        let next_output = opening(&sender, 1)?;
        let next_body = encrypted_body(
            context,
            PaymentInputs::new(
                checkpoint.state().note_anchor().root(),
                vec![marker],
                limits(),
            )?,
            &[(&sender, &next_output)],
            2,
        )?;
        let witness = [SpendWitness::new(
            &recovered,
            &recipient.spending,
            &recipient.nullifier,
            &path,
        )];
        let proof = prove_payment_body(
            &next_body,
            &checkpoint.state().note_anchor(),
            &witness,
            &[&next_output],
            &mut measurement,
        )?;
        (
            PaymentEnvelope::new(next_body, proof),
            accepted.position(),
            marker,
        )
    };
    drop(preliminary);
    let next = occurrence(next_envelope.into(), 2, 13, 0);
    let public = run(m, vec![first_unit, vec![next]], measurement)?;
    assert_eq!(public.checkpoints.len(), 2);
    let payment_index = if workload == Workload::FailedEarlyCopy {
        1
    } else {
        0
    };
    assert_eq!(
        public.checkpoints[0].effects()[payment_index]
            .accepted
            .as_ref()
            .unwrap()
            .after_pool
            .atoms(),
        96
    );
    assert_eq!(public.checkpoints[0].state().pool().atoms(), 99);
    assert_eq!(public.checkpoints[1].state().pool().atoms(), 97);
    if workload == Workload::SharedBeneficiary {
        assert_eq!(
            public.checkpoints[1]
                .state()
                .account(public.manifest.accounts[0].0)
                .unwrap()
                .balance()
                .atoms(),
            3
        );
    } else {
        assert_eq!(
            public.checkpoints[0]
                .state()
                .account(public.manifest.accounts[0].0)
                .unwrap()
                .balance()
                .atoms(),
            0
        );
        assert_eq!(
            public.checkpoints[1]
                .state()
                .account(public.manifest.accounts[1].0)
                .unwrap()
                .balance()
                .atoms(),
            1
        );
        assert_eq!(
            public.checkpoints[1]
                .state()
                .account(public.manifest.accounts[2].0)
                .unwrap()
                .balance()
                .atoms(),
            2
        );
    }
    for accepted in public.checkpoints[0].accepted_outputs() {
        if let houseki_ledger::OutputBody::RewardWithdrawal(body) = accepted.body() {
            let recovered =
                recover_withdrawal_output(body, &recipient.recipient, &recipient.decryption, 4096)?;
            assert_eq!(accepted.position(), withdrawal_position);
            assert_eq!(
                derive_nullifier(&recovered, &recipient.nullifier, &accepted.position())?,
                expected_marker
            );
        }
    }
    if workload == Workload::FailedEarlyCopy {
        use houseki_types::{ExecutionOutcome as O, ExecutionRejectionReason as R};
        assert_eq!(
            public.checkpoints[0]
                .receipts()
                .iter()
                .map(|r| r.outcome())
                .collect::<Vec<_>>(),
            vec![
                O::Rejected(R::InsufficientBalance),
                O::Accepted,
                O::Accepted,
                O::Rejected(R::WrongNonce)
            ]
        );
    }
    Ok(public)
}

/// Full real-proof local execution consumers.
#[cfg(all(test, feature = "prover"))]
mod tests {
    use crate::{Workload, generate};

    /// Pins the fee-funded withdrawal and recovered-note respend to the exact development amounts.
    #[test]
    fn real_value_loop_matches_fixed_accounting() {
        let directory =
            std::env::temp_dir().join(format!("houseki-ledger-loop-{}", std::process::id()));
        if directory.exists() {
            std::fs::remove_dir_all(&directory).unwrap();
        }
        let fixture = generate(Workload::ValueLoop, &directory).unwrap();
        let checkpoints = fixture.checkpoints();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(
            checkpoints[0].effects()[0]
                .accepted
                .as_ref()
                .unwrap()
                .after_pool
                .atoms(),
            96
        );
        assert_eq!(checkpoints[0].state().pool().atoms(), 99);
        assert_eq!(checkpoints[1].state().pool().atoms(), 97);
        assert_eq!(checkpoints[0].accepted_outputs().count(), 3);
        assert_eq!(checkpoints[1].accepted_outputs().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Every admitted payment family produces actual accepted effects and recoverable output views.
    #[test]
    fn all_shapes_execute_with_actual_verification() {
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let directory = std::env::temp_dir().join(format!(
                    "houseki-ledger-shape-{inputs}-{outputs}-{}",
                    std::process::id()
                ));
                if directory.exists() {
                    std::fs::remove_dir_all(&directory).unwrap();
                }
                let fixture = generate(Workload::Payment { inputs, outputs }, &directory).unwrap();
                assert_eq!(
                    fixture.checkpoints()[0].state().pool().atoms(),
                    inputs as u128 * 100 - (inputs + outputs) as u128
                );
                assert_eq!(fixture.checkpoints()[0].accepted_outputs().count(), outputs);
                std::fs::remove_dir_all(directory).unwrap();
            }
        }
    }
}
