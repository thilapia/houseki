//! Complete experimental payments with real delivery, append and subsequent spending.
//!
//! Run with `--features prover,experimental-profiles --example payment --release`.
//!
//! Counts default to four inputs and two outputs, with optional `--inputs`, `--outputs`,
//! `--directory` and `--repeated` arguments.
//!
//! All state is synthetic and local, and retained artifacts contain public data only.

mod artifacts;
mod fixture;
mod options;
mod owner;
mod policy;

use fixture::{Fixture, encrypted_body, limits, opening};
use houseki_notes::{SpendWitness, derive_nullifier, recover_payment_output};
use houseki_proofs::{
    CancellationToken, PaymentWitness, ProofAllocator, ProofContext, ProofRuntime, prove_payment,
    verify_payment,
};
use houseki_state::NoteTree;
use houseki_types::PaymentInputs;
use options::Options;
use policy::Policy;
use std::{alloc::System, error::Error, path::Path, time::Instant};

/// Enables cleanup of every allocation owned by an admitted private attempt.
#[global_allocator]
static ALLOCATOR: ProofAllocator<System> = ProofAllocator::new(System);

/// Runs the bounded public demonstration without applying any external ledger state.
fn main() -> Result<(), Box<dyn Error>> {
    let options = Options::parse(std::env::args().skip(1))?;

    run(
        options.inputs,
        options.outputs,
        options.repeated,
        options.directory.as_deref(),
    )
}

/// Proves a complete payment, demonstrates external acceptance checks and spends recovered outputs.
fn run(
    inputs: usize,
    outputs: usize,
    repeated: bool,
    directory: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let mut fixture = Fixture::new(inputs, outputs, repeated)?;
    let context = ProofContext::new(fixture.body.context())?;
    let preparation = start.elapsed();
    let start = Instant::now();
    let proof = {
        let spends = fixture.spends();
        let outputs = fixture.outputs();
        let witness = PaymentWitness::new(&spends, &outputs)?;
        prove_payment(
            &ProofRuntime::new(),
            &fixture.body,
            &fixture.anchor,
            &witness,
            &context,
            &CancellationToken::new(),
        )?
    };

    let proving = start.elapsed();
    let runtime = ProofRuntime::new();
    let start = Instant::now();
    let evidence = verify_payment(&runtime, &fixture.body, &fixture.anchor, &proof, &context)?;
    let verification = start.elapsed();
    let mut policy = Policy::new(fixture.anchor);
    policy.check(&evidence)?;
    policy.eligible = NoteTree::new(context.expected().network_id())?.anchor();
    assert_eq!(policy.check(&evidence), Err("ineligible anchor"));
    policy.eligible = fixture.anchor;
    policy.record(&evidence)?;
    assert_eq!(policy.check(&evidence), Err("already spent input"));

    let mut recovered = Vec::new();
    for index in 0..outputs {
        let owner = fixture.output_owner(index);
        let note = recover_payment_output(
            &fixture.body,
            index as u64,
            &owner.recipient,
            &owner.decryption,
            limits(),
            4096,
        )?;
        assert_eq!(
            note.commitment()?,
            fixture.body.outputs().outputs()[index].commitment()
        );
        assert_eq!(note.amount(), fixture.outputs()[index].amount());
        recovered.push(note);
    }

    let positions = fixture
        .body
        .outputs()
        .outputs()
        .iter()
        .map(|output| fixture.tree.append(output.commitment()))
        .collect::<Result<Vec<_>, _>>()?;
    if repeated {
        assert_eq!(recovered[0].commitment()?, recovered[1].commitment()?);
        assert_ne!(positions[0], positions[1]);
        assert_ne!(
            fixture.body.outputs().outputs()[0].envelope(),
            fixture.body.outputs().outputs()[1].envelope()
        );
    }

    if let Some(directory) = directory {
        artifacts::write(directory, &fixture.body, &fixture.anchor, &proof, &context)?;
    }

    println!(
        "experimental payment: inputs={inputs} outputs={outputs} repeated={repeated} fixture_ms={} prove_ms={} verify_ms={} proof_bytes={} body_bytes={}",
        preparation.as_millis(),
        proving.as_millis(),
        verification.as_millis(),
        proof.byte_len(),
        fixture.body.to_bytes(context.body_limits())?.len()
    );
    let start = Instant::now();
    let spend_count = if repeated { 2 } else { 1 };
    let anchor = fixture.tree.anchor();
    let paths = positions[..spend_count]
        .iter()
        .map(|position| fixture.tree.witness(position))
        .collect::<Result<Vec<_>, _>>()?;
    let spends: Vec<_> = recovered[..spend_count]
        .iter()
        .zip(&paths)
        .map(|(note, path)| {
            SpendWitness::new(
                note,
                &fixture.receiver.spending,
                &fixture.receiver.nullifier,
                path,
            )
        })
        .collect();
    let markers = recovered[..spend_count]
        .iter()
        .zip(&positions)
        .map(|(note, position)| derive_nullifier(note, &fixture.receiver.nullifier, position))
        .collect::<Result<Vec<_>, _>>()?;
    if repeated {
        assert_ne!(markers[0], markers[1]);
    }

    let total: u128 = recovered[..spend_count]
        .iter()
        .map(|note| note.amount().atoms())
        .sum();
    let next_output = opening(&fixture.sender, total - 1)?;
    let next_body = encrypted_body(
        context.expected(),
        PaymentInputs::new(anchor.root(), markers, limits())?,
        &[(&fixture.sender, &next_output)],
        1,
    )?;
    let next_outputs = [&next_output];
    let witness = PaymentWitness::new(&spends, &next_outputs)?;
    let next_proof = prove_payment(
        &runtime,
        &next_body,
        &anchor,
        &witness,
        &context,
        &CancellationToken::new(),
    )?;
    let next_evidence = verify_payment(&runtime, &next_body, &anchor, &next_proof, &context)?;
    policy.eligible = anchor;
    policy.record(&next_evidence)?;
    let recovered_again = recover_payment_output(
        &next_body,
        0,
        &fixture.sender.recipient,
        &fixture.sender.decryption,
        limits(),
        4096,
    )?;
    assert_eq!(recovered_again.commitment()?, next_output.commitment()?);
    assert_eq!(recovered_again.amount(), next_output.amount());
    if let Some(directory) = directory {
        artifacts::write(
            &directory.join("respend"),
            &next_body,
            &anchor,
            &next_proof,
            &context,
        )?;
    }

    println!(
        "recovery, ordered append and respend verified: respend_inputs={spend_count} respend_ms={} respend_proof_bytes={}",
        start.elapsed().as_millis(),
        next_proof.byte_len()
    );
    println!("authentic proof rejected by spent-set and anchor-eligibility policies");
    println!(
        "fee policy, activation, tree capacity and atomic execution remain consumer obligations"
    );

    Ok(())
}

/// Native delivery and complete consumer integration for the priority envelope.
#[cfg(test)]
mod tests {
    use super::*;

    /// Four inputs support both recipient plus change and an exact one-output payment with fees.
    #[test]
    fn payment_priority_delivery_and_respend() {
        run(4, 2, false, None).unwrap();
        run(4, 1, false, None).unwrap();
    }

    /// Repeated commitments remain separately funded occurrences with distinct original positions.
    #[test]
    fn payment_repeated_outputs_respend_at_distinct_positions() {
        run(2, 2, true, None).unwrap();
    }
}
