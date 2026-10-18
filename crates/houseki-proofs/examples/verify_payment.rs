//! Independent payment verifier without witness dependencies, protected allocator or proving entropy.
//!
//! Supply a public artifact directory followed by an independently expected root in hexadecimal
//! and its decimal occupied count under the demonstration's fixed context.

use houseki_proofs::{EXPERIMENTAL_PAYMENT_PROFILE, ProofContext, ProofRuntime, verify_payment};
use houseki_types::{
    CheckpointSequence, EncodedTransactionProof, FeeScheduleId, NetworkId, NoteCount, NoteRoot,
    NoteTreeAnchor, PaymentBody, ProtocolVersion, TransactionContext, ValidityCheckpointRange,
};
use std::{
    error::Error,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

/// Verifies retained public artifacts against independently supplied anchor metadata.
fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let directory = PathBuf::from(
        args.next()
            .ok_or("expected artifact directory, expected root and count")?,
    );
    let root = parse_root(&args.next().ok_or("expected independent root")?)?;
    let count = NoteCount::new(args.next().ok_or("expected independent count")?.parse()?)?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }

    let expected = TransactionContext::new(
        NetworkId::from_bytes([7; 64]),
        ProtocolVersion::new(1),
        EXPERIMENTAL_PAYMENT_PROFILE,
        FeeScheduleId::new(4),
        ValidityCheckpointRange::new(CheckpointSequence::new(5), CheckpointSequence::new(8))?,
    );
    let context = ProofContext::new(expected)?;
    let anchor = NoteTreeAnchor::new(expected.network_id(), count, root);
    let body = PaymentBody::from_bytes(
        &read_bounded(
            &directory.join("body.bin"),
            context.body_limits().max_body_bytes(),
        )?,
        context.body_limits(),
    )?;
    let proof = EncodedTransactionProof::new(
        read_bounded(&directory.join("proof.bin"), context.max_proof_bytes())?,
        context.max_proof_bytes(),
    )?;
    let start = Instant::now();
    let runtime = ProofRuntime::new();
    let evidence = verify_payment(&runtime, &body, &anchor, &proof, &context)?;
    println!(
        "verified experimental payment: inputs={} outputs={} proof_bytes={} body_bytes={} verify_ms={}",
        evidence.body().inputs().input_count(),
        evidence.body().outputs().output_count(),
        proof.byte_len(),
        body.to_bytes(context.body_limits())?.len(),
        start.elapsed().as_millis()
    );
    println!("unspentness, eligible anchors, fees and atomic execution require consumer checks");

    Ok(())
}

/// Parses one exact public digest without permitting missing or trailing digits.
fn parse_root(value: &str) -> Result<NoteRoot, Box<dyn Error>> {
    if value.len() != 128 || !value.is_ascii() {
        return Err("expected 128 hexadecimal root digits".into());
    }

    let mut root = [0; 64];
    for (index, byte) in root.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }

    Ok(NoteRoot::from_bytes(root))
}

/// Caps file input before parsing, including one byte needed to detect excess.
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

/// Exact independently provided root representation checks.
#[cfg(test)]
mod tests {
    use super::*;

    /// Root parsing accepts one full digest and rejects missing, trailing and nonhex characters.
    #[test]
    fn expected_root_is_exact() {
        assert_eq!(parse_root(&"07".repeat(64)).unwrap().as_bytes(), &[7; 64]);
        for value in [
            "07".repeat(63),
            "07".repeat(65),
            "gg".repeat(64),
            "é".repeat(64),
        ] {
            assert!(parse_root(&value).is_err());
        }
    }
}
