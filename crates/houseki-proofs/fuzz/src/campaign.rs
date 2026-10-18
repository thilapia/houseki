//! Fixed statement attacks and reproducible bounded public-verifier campaigns.

use crate::{allocation, body::Body, mutation, seed::Seed};
use houseki_proofs::{ProofContext, ProofRuntime, VerifyError};
use houseki_types::{
    EncodedTransactionProof, NoteCount, NoteTreeAnchor, PaymentBody, RewardWithdrawalBody,
};
use std::{
    error::Error,
    time::{Duration, Instant},
};

/// Maximum observed live verifier allocation, separate from the fixed decoder vector cap.
const MAX_LIVE_BYTES: usize = 128 * 1024 * 1024;

/// Per-case verifier deadline enforced after return and by the external campaign supervisor.
const MAX_CASE_TIME: Duration = Duration::from_secs(5);

/// Checks valid seeds and rejects every ordered field occurrence and every cross-seed proof.
pub(crate) fn conformance(seeds: &[Seed]) -> Result<(), Box<dyn Error>> {
    let runtime = ProofRuntime::new();
    for seed in seeds {
        let (result, peak) =
            allocation::measure(|| seed.body.verify(&seed.proof, &seed.context, &runtime));
        result?;
        assert!(peak <= MAX_LIVE_BYTES);
        println!("valid seed={} peak_live_bytes={peak}", seed.name);
        let (inputs, payloads) = match &seed.body {
            Body::Payment { body, .. } => (
                Some(body.inputs().input_count()),
                body.outputs()
                    .outputs()
                    .iter()
                    .map(|output| output.envelope().payload().len())
                    .collect::<Vec<_>>(),
            ),
            Body::Withdrawal(body) => (None, vec![body.output().envelope().payload().len()]),
        };
        let regions = mutation::body_regions(&seed.bytes, inputs, &payloads);
        let mut mutations = 0;
        let mut cryptographic = 0;
        for region in &regions {
            for offset in [region.start, region.end - 1] {
                let mut changed = seed.bytes.clone();
                changed[offset] ^= 1;
                let result = body_result(seed, &changed, &runtime);
                assert!(
                    !matches!(result, Some(Ok(()))),
                    "{} body byte {offset}",
                    seed.name
                );
                cryptographic +=
                    usize::from(matches!(result, Some(Err(VerifyError::InvalidProof))));
                mutations += 1;
            }
        }

        if let Body::Payment { body, anchor } = &seed.body {
            for count in [0, 1, (1_u128 << 64) - 1, 1_u128 << 64] {
                if count == anchor.count().value() {
                    continue;
                }

                let changed = Body::Payment {
                    body: body.clone(),
                    anchor: NoteTreeAnchor::new(
                        anchor.network_id(),
                        NoteCount::new(count)?,
                        anchor.root(),
                    ),
                };
                assert!(
                    changed
                        .verify(&seed.proof, &seed.context, &runtime)
                        .is_err()
                );
            }

            let input_count = body.inputs().input_count();
            if input_count > 1 {
                let mut changed = seed.bytes.clone();
                let (first, second) = changed[172..300].split_at_mut(64);
                first.swap_with_slice(second);
                assert!(!matches!(
                    body_result(seed, &changed, &runtime),
                    Some(Ok(()))
                ));

                let mut changed = seed.bytes.clone();
                changed[236..300].copy_from_slice(&seed.bytes[172..236]);
                assert!(!matches!(
                    body_result(seed, &changed, &runtime),
                    Some(Ok(()))
                ));
            }

            if payloads.len() == 2 {
                let first = 196 + 64 * input_count;
                let second = first + 1640 + payloads[0];
                let mut changed = seed.bytes[..first].to_vec();
                changed.extend_from_slice(&seed.bytes[second..]);
                changed.extend_from_slice(&seed.bytes[first..second]);
                assert!(!matches!(
                    body_result(seed, &changed, &runtime),
                    Some(Ok(()))
                ));
            }
        }

        for other in seeds {
            if other.name == seed.name {
                continue;
            }

            assert!(
                seed.body
                    .verify(&other.proof, &seed.context, &runtime)
                    .is_err(),
                "{} accepted {}",
                seed.name,
                other.name
            );
            let mut substituted = other.proof.as_bytes().to_vec();
            substituted[..88].copy_from_slice(&seed.proof.as_bytes()[..88]);
            let substituted = EncodedTransactionProof::new(substituted, usize::MAX)?;
            assert!(
                seed.body
                    .verify(&substituted, &seed.context, &runtime)
                    .is_err(),
                "{} accepted reheadered {}",
                seed.name,
                other.name
            );
        }

        for offset in 0..104 {
            let mut changed = seed.proof.as_bytes().to_vec();
            changed[offset] ^= 1;
            let proof = EncodedTransactionProof::new(changed, usize::MAX)?;
            assert!(
                seed.body.verify(&proof, &seed.context, &runtime).is_err(),
                "{} proof header byte {offset}",
                seed.name
            );
        }

        println!(
            "conformance seed={} fields={} body_mutations={mutations} cryptographic_body_rejections={cryptographic} header_mutations=104 cross_seed_checks={}",
            seed.name,
            regions.len(),
            2 * (seeds.len() - 1)
        );
    }

    Ok(())
}

/// Parses a changed body independently and, when recognized, adopts its context to test transcript binding.
fn body_result(
    seed: &Seed,
    bytes: &[u8],
    runtime: &ProofRuntime,
) -> Option<Result<(), VerifyError>> {
    let body = match &seed.body {
        Body::Payment { anchor, .. } => {
            let Ok(body) = PaymentBody::from_bytes(bytes, seed.context.body_limits()) else {
                return None;
            };
            let anchor = NoteTreeAnchor::new(
                body.context().network_id(),
                anchor.count(),
                body.inputs().anchor(),
            );

            Body::Payment {
                body: Box::new(body),
                anchor,
            }
        }
        Body::Withdrawal(_) => {
            let Ok(body) = RewardWithdrawalBody::from_bytes(bytes, seed.context.body_limits())
            else {
                return None;
            };

            Body::Withdrawal(Box::new(body))
        }
    };
    let Ok(context) = ProofContext::new(body.context()) else {
        return None;
    };

    Some(body.verify(&seed.proof, &context, runtime))
}

/// Locates every variable frontier count in one validated seed using the published fixed schema.
fn frontiers(seed: &Seed) -> Vec<usize> {
    let bytes = seed.proof.as_bytes();
    let rounds = u32::from_le_bytes(bytes[96..100].try_into().unwrap()) as usize;
    let width = if matches!(seed.body, Body::Payment { .. }) {
        1185
    } else {
        1493
    };
    let mut cursor = 104 + 3 * 64 + 2 * width * 24 + 9 * 72 + 11 * 72 + rounds * 64;
    let mut offsets = Vec::new();
    for (matrices, committed_width) in [(1, 6), (1, width + 3), (8, 6)] {
        cursor += 128 * matrices * (committed_width * 8 + 32);
        offsets.push(cursor);
        let count = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4 + count * 64;
    }

    for _ in 0..rounds {
        cursor += 128 * (24 + 32);
        offsets.push(cursor);
        let count = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4 + count * 64;
    }

    assert_eq!(cursor + 24, bytes.len());

    offsets
}

/// Mutates complete valid proofs without catching panics or treating every byte change as a forgery.
///
/// Accepted changed proof bytes are counted for review because proof malleability alone need not
/// change the verified statement.
pub(crate) fn fuzz(
    seeds: &[Seed],
    duration: Duration,
    mut random: u64,
) -> Result<(), Box<dyn Error>> {
    if random == 0 {
        return Err("mutation seed must be nonzero".into());
    }

    let runtime = ProofRuntime::new();
    let offsets: Vec<_> = seeds.iter().map(frontiers).collect();
    for seed in seeds {
        seed.body.verify(&seed.proof, &seed.context, &runtime)?;
    }

    let started = Instant::now();
    let mut iteration = 0;
    let mut accepted = 0;
    let mut peak = 0;
    let mut longest = Duration::ZERO;
    let mut kinds = [0_usize; 10];
    let mut hits = vec![0_usize; seeds.len()];
    while started.elapsed() < duration {
        let index = iteration % seeds.len();
        let seed = &seeds[index];
        let bytes = mutation::proof(
            seed.proof.as_bytes(),
            &offsets[index],
            iteration,
            &mut random,
        );
        let proof = EncodedTransactionProof::new(bytes, usize::MAX)?;
        println!(
            "case iteration={iteration} seed={} kind={}",
            seed.name,
            iteration % 10
        );
        let begin = Instant::now();
        let (result, allocated) =
            allocation::measure(|| seed.body.verify(&proof, &seed.context, &runtime));
        let elapsed = begin.elapsed();
        assert!(
            allocated <= MAX_LIVE_BYTES,
            "iteration {iteration} allocation {allocated}"
        );
        assert!(
            elapsed <= MAX_CASE_TIME,
            "iteration {iteration} exceeded verifier deadline"
        );
        if result.is_ok() {
            accepted += 1;
            println!(
                "accepted changed proof iteration={iteration} seed={}",
                seed.name
            );
        }

        peak = peak.max(allocated);
        longest = longest.max(elapsed);
        kinds[iteration % 10] += 1;
        hits[index] += 1;
        iteration += 1;
    }

    assert!(kinds.iter().all(|count| *count > 0));
    assert!(hits.iter().all(|count| *count > 0));
    for seed in seeds {
        seed.body.verify(&seed.proof, &seed.context, &runtime)?;
    }

    println!(
        "fuzz iterations={iteration} elapsed_ms={} accepted_changed={accepted} peak_live_bytes={peak} max_case_ms={} kinds={kinds:?} seeds={hits:?} final_random={random}",
        started.elapsed().as_millis(),
        longest.as_millis()
    );

    Ok(())
}

/// Reproduces one indexed mutation without spending verifier work on earlier inputs.
pub(crate) fn replay(
    seeds: &[Seed],
    iteration: usize,
    mut random: u64,
) -> Result<(), Box<dyn Error>> {
    if random == 0 || iteration > 1_000_000 {
        return Err("replay requires a nonzero seed and at most one million iterations".into());
    }

    let offsets: Vec<_> = seeds.iter().map(frontiers).collect();
    for current in 0..=iteration {
        let index = current % seeds.len();
        let seed = &seeds[index];
        let bytes = mutation::proof(seed.proof.as_bytes(), &offsets[index], current, &mut random);
        if current == iteration {
            let proof = EncodedTransactionProof::new(bytes, usize::MAX)?;
            let (result, peak) = allocation::measure(|| {
                seed.body
                    .verify(&proof, &seed.context, &ProofRuntime::new())
            });
            assert!(peak <= MAX_LIVE_BYTES);
            println!(
                "replay iteration={iteration} seed={} result={result:?} peak_live_bytes={peak}",
                seed.name
            );
        }
    }

    Ok(())
}
