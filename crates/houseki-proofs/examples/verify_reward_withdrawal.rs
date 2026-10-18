//! Verifier consumer that needs neither the prover feature, a protected allocator nor private state.
//!
//! Run with `--features experimental-profiles --example verify_reward_withdrawal --release` and
//! the public artifact directory produced by the withdrawal example.
//!
//! Expected rules are fixed independently to that demonstration's public configuration.

use houseki_proofs::{
    EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE, ProofContext, ProofRuntime, verify_reward_withdrawal,
};
use houseki_types::{
    CheckpointSequence, EncodedTransactionProof, FeeScheduleId, NetworkId, ProtocolVersion,
    RewardWithdrawalBody, TransactionContext, ValidityCheckpointRange,
};
use std::{
    error::Error,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

/// Verifies public bytes with independently fixed expected rules and no private owners.
fn main() -> Result<(), Box<dyn Error>> {
    let directory = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("expected a public artifact directory")?;
    let expected = TransactionContext::new(
        NetworkId::from_bytes([7; 64]),
        ProtocolVersion::new(1),
        EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE,
        FeeScheduleId::new(4),
        ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))?,
    );
    let context = ProofContext::new(expected)?;
    let body = RewardWithdrawalBody::from_bytes(
        &read_bounded(&directory.join("body.bin"), 16384)?,
        context.body_limits(),
    )?;
    let bytes = read_bounded(&directory.join("proof.bin"), context.max_proof_bytes())?;
    let proof = EncodedTransactionProof::new(bytes, context.max_proof_bytes())?;
    let runtime = ProofRuntime::new();
    let start = Instant::now();
    let evidence = verify_reward_withdrawal(&runtime, &body, &proof, &context)?;

    println!(
        "verified experimental output: proof_bytes={} verify_ms={} public_atoms={}",
        proof.byte_len(),
        start.elapsed().as_millis(),
        evidence.body().public_amount().atoms()
    );
    println!("source signature and account execution checks remain independent");

    Ok(())
}

/// Caps file input before canonical decoding, including a single byte needed to detect excess.
fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("public artifact exceeds its byte limit".into());
    }

    Ok(bytes)
}
