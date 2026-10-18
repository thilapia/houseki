//! Exclusive creation of public interoperability artifacts without retaining private owners.

use houseki_proofs::ProofContext;
use houseki_types::{EncodedTransactionProof, NoteTreeAnchor, PaymentBody};
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

/// Writes canonical public effects and the producer's independently known expected anchor.
pub(super) fn write(
    directory: &Path,
    body: &PaymentBody,
    anchor: &NoteTreeAnchor,
    proof: &EncodedTransactionProof,
    context: &ProofContext,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(directory)?;
    let body = body.to_bytes(context.body_limits())?;
    let count = anchor.count().value().to_le_bytes();
    for (name, bytes) in [
        ("body.bin", body.as_slice()),
        ("proof.bin", proof.as_bytes()),
        ("anchor-count.bin", count.as_slice()),
        ("anchor-root.bin", anchor.root().as_bytes().as_slice()),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))?;
        file.write_all(bytes)?;
    }

    Ok(())
}
