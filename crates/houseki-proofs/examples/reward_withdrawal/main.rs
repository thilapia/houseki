//! Real experimental withdrawal proving, authenticated delivery and separate source signatures.
//!
//! Run with `--features prover,experimental-profiles --example reward_withdrawal --release`.
//!
//! An optional output directory receives public body and proof bytes for independent verification.
//!
//! The example does not apply account state or qualify the candidate for production activation.

mod fixture;

use fixture::Fixture;
use houseki_crypto::MlDsa87VerificationKey;
use houseki_notes::recover_withdrawal_output;
use houseki_proofs::{
    CancellationToken, ProofAllocator, ProofContext, ProofRuntime, VerifiedRewardWithdrawal,
    prove_reward_withdrawal, verify_reward_withdrawal,
};
use houseki_types::EncodedMlDsa87Signature;
use std::{
    alloc::System,
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::Instant,
};

/// Enables the library's private allocation cleanup boundary for this native process.
#[global_allocator]
static ALLOCATOR: ProofAllocator<System> = ProofAllocator::new(System);

/// Runs fresh proving and recovery, optionally retaining only public interoperability artifacts.
fn main() -> Result<(), Box<dyn Error>> {
    let directory = std::env::args_os().nth(1).map(std::path::PathBuf::from);

    run(directory.as_deref())
}

/// Exercises the same public family APIs used by native consumers, including independent checks.
fn run(directory: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let context = ProofContext::new(fixture.body.context())?;
    let authority = fixture.authority.verification_key();
    let signature = fixture
        .authority
        .sign_reward_withdrawal(&fixture.body, context.body_limits())?;
    let start = Instant::now();
    let proof = {
        let runtime = ProofRuntime::new();
        prove_reward_withdrawal(
            &runtime,
            &fixture.body,
            &fixture.opening,
            &context,
            &CancellationToken::new(),
        )?
    };

    let proving = start.elapsed();
    drop(fixture.opening);

    let runtime = ProofRuntime::new();
    let start = Instant::now();
    let evidence = verify_reward_withdrawal(&runtime, &fixture.body, &proof, &context)?;
    let verification = start.elapsed();
    check_source_signature(&evidence, &authority, &signature)?;
    let invalid_signature =
        EncodedMlDsa87Signature::from_bytes([0; EncodedMlDsa87Signature::BYTE_LENGTH]);
    assert!(check_source_signature(&evidence, &authority, &invalid_signature).is_err());

    let recovered =
        recover_withdrawal_output(&fixture.body, &fixture.recipient, &fixture.decryption, 4096)?;
    assert_eq!(recovered.commitment()?, fixture.body.output().commitment());
    assert_eq!(recovered.amount(), &fixture.body.public_amount());
    drop(recovered);

    if let Some(directory) = directory {
        fs::create_dir_all(directory)?;
        let body = fixture.body.to_bytes(context.body_limits())?;
        for (name, bytes) in [
            ("body.bin", body.as_slice()),
            ("proof.bin", proof.as_bytes()),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(name))?;
            file.write_all(bytes)?;
        }
    }

    println!(
        "experimental withdrawal: proof_bytes={} prove_ms={} verify_ms={}",
        proof.byte_len(),
        proving.as_millis(),
        verification.as_millis()
    );
    println!("recipient recovery and source signature checked; invalid signature rejected");
    println!(
        "account balance, nonce eligibility, fee policy and activation require independent state checks"
    );

    Ok(())
}

/// Requires the independent source authority and signature in addition to output proof evidence.
fn check_source_signature(
    evidence: &VerifiedRewardWithdrawal<'_>,
    authority: &MlDsa87VerificationKey,
    signature: &EncodedMlDsa87Signature,
) -> Result<(), Box<dyn Error>> {
    let body = evidence.body();
    if authority.reward_account_id(evidence.context().expected().network_id())?
        != body.reward_account_id()
    {
        return Err("source account does not match the independently supplied authority".into());
    }

    authority.verify_reward_withdrawal(body, signature, evidence.context().body_limits())?;

    Ok(())
}

/// The example's composed consumer must not confuse output evidence with source authorization.
#[cfg(test)]
mod tests {
    use super::*;

    /// A valid output proof with a malformed source signature still fails the composed consumer.
    #[test]
    fn withdrawal_output_proof_requires_separate_signature() {
        run(None).unwrap();
    }
}
