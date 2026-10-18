//! Fresh public proving attempts reusing the original native demonstration owners.

use crate::{Error, PublicArtifact, Sample, Workload, payment_fixture, withdrawal_fixture};
use houseki_proofs::{
    CancellationToken, PaymentWitness, ProofContext, ProofRuntime, prove_payment,
    prove_reward_withdrawal,
};
use std::time::Instant;

/// Proves and verifies one fresh synthetic statement without retaining any private owner.
///
/// Fixture generation is measured separately from the complete context, witness and encoded
/// proving API boundary because native key generation is not part of proof latency.
///
/// # Errors
///
/// Returns public fixture, proving or verification failures without producing a success sample.
pub fn produce(
    workload: Workload,
    runtime: &ProofRuntime,
    token: &CancellationToken,
) -> Result<(PublicArtifact, Sample), Error> {
    runtime.check_prover_allocator().map_err(operation)?;
    let fixture_start = Instant::now();
    let (artifact, fixture_us, prove_api_us, body_encode_us) = if let Some((inputs, outputs)) =
        workload.counts()
    {
        let fixture = payment_fixture::Fixture::new(inputs, outputs, false).map_err(operation)?;
        let fixture_us = fixture_start.elapsed().as_micros();
        let start = Instant::now();
        let context = ProofContext::new(workload.context()).map_err(operation)?;
        let spends = fixture.spends();
        let outputs = fixture.outputs();
        let witness = PaymentWitness::new(&spends, &outputs).map_err(operation)?;
        let proof = prove_payment(
            runtime,
            &fixture.body,
            &fixture.anchor,
            &witness,
            &context,
            token,
        )
        .map_err(operation)?;
        let prove_api_us = start.elapsed().as_micros();
        let start = Instant::now();
        let body = fixture
            .body
            .to_bytes(context.body_limits())
            .map_err(operation)?;
        let body_encode_us = start.elapsed().as_micros();

        (
            PublicArtifact {
                workload,
                body,
                proof,
                anchor: Some((
                    *fixture.anchor.root().as_bytes(),
                    fixture.anchor.count().value(),
                )),
            },
            fixture_us,
            prove_api_us,
            body_encode_us,
        )
    } else {
        let fixture = withdrawal_fixture::Fixture::new().map_err(operation)?;
        let fixture_us = fixture_start.elapsed().as_micros();
        let start = Instant::now();
        let context = ProofContext::new(workload.context()).map_err(operation)?;
        let proof =
            prove_reward_withdrawal(runtime, &fixture.body, &fixture.opening, &context, token)
                .map_err(operation)?;
        let prove_api_us = start.elapsed().as_micros();
        let start = Instant::now();
        let body = fixture
            .body
            .to_bytes(context.body_limits())
            .map_err(operation)?;
        let body_encode_us = start.elapsed().as_micros();

        (
            PublicArtifact {
                workload,
                body,
                proof,
                anchor: None,
            },
            fixture_us,
            prove_api_us,
            body_encode_us,
        )
    };
    let mut sample = artifact.verify(runtime)?;
    sample.fixture_us = Some(fixture_us);
    sample.prove_api_us = Some(prove_api_us);
    sample.body_encode_us = Some(body_encode_us);

    Ok((artifact, sample))
}

/// Retains a public failure description rather than any input or protected owner.
fn operation(error: impl std::fmt::Display) -> Error {
    Error::Operation(error.to_string())
}
