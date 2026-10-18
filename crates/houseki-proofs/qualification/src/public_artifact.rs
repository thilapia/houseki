//! Size bounded public artifact input without any protected owner dependency.

use crate::{Error, Sample, Workload};
use houseki_proofs::{ProofContext, ProofRuntime, verify_payment, verify_reward_withdrawal};
use houseki_types::{
    EncodedTransactionProof, NoteCount, NoteRoot, NoteTreeAnchor, PaymentBody, RewardWithdrawalBody,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::Instant,
};

/// Only public statement bytes, proof bytes and independently retained payment anchor metadata.
pub struct PublicArtifact {
    /// Expected workload, never selected by a proof header.
    pub(crate) workload: Workload,

    /// Canonical body bytes under the fixed 16 KiB cap.
    pub(crate) body: Vec<u8>,

    /// Encoded proof under the fixed 2 MiB cap.
    pub(crate) proof: EncodedTransactionProof,

    /// Trusted payment root and occupied count supplied with this synthetic producer artifact.
    pub(crate) anchor: Option<([u8; 64], u128)>,
}

impl PublicArtifact {
    /// Loads public bytes under fixed limits without deriving trusted rules from their headers.
    ///
    /// The caller must trust the producer's anchor metadata independently of proof validity.
    ///
    /// # Errors
    ///
    /// Rejects unavailable or oversized files and incorrectly sized anchor metadata.
    pub fn load(directory: &Path, workload: Workload) -> Result<Self, Error> {
        let body = read_bounded(File::open(directory.join("body.bin"))?, 16384)?;
        let proof = EncodedTransactionProof::new(
            read_bounded(File::open(directory.join("proof.bin"))?, 2097152)?,
            2097152,
        )
        .map_err(|error| Error::Operation(error.to_string()))?;
        let anchor = if workload.counts().is_some() {
            let root = read_bounded(File::open(directory.join("anchor-root.bin"))?, 64)?;
            let count = read_bounded(File::open(directory.join("anchor-count.bin"))?, 16)?;
            Some((
                root.try_into()
                    .map_err(|_| Error::Input("expected 64 root bytes"))?,
                u128::from_le_bytes(
                    count
                        .try_into()
                        .map_err(|_| Error::Input("expected 16 count bytes"))?,
                ),
            ))
        } else {
            None
        };

        Ok(Self {
            workload,
            body,
            proof,
            anchor,
        })
    }

    /// Verifies the entire loaded statement through the public experimental facade.
    ///
    /// This establishes no signature authorization, anchor eligibility or ledger acceptance.
    ///
    /// # Errors
    ///
    /// Rejects malformed bodies, unsupported shapes, inconsistent anchors and invalid proofs.
    pub fn verify(&self, runtime: &ProofRuntime) -> Result<Sample, Error> {
        let start = Instant::now();
        let context = ProofContext::new(self.workload.context())
            .map_err(|error| Error::Operation(error.to_string()))?;
        let (decode_us, verify_api_us) = if let Some((inputs, outputs)) = self.workload.counts() {
            let body = PaymentBody::from_bytes(&self.body, context.body_limits())
                .map_err(|error| Error::Operation(error.to_string()))?;
            if body.inputs().input_count() != inputs || body.outputs().output_count() != outputs {
                return Err(Error::Input(
                    "body does not match the independently selected shape",
                ));
            }

            let (root, count) = self.anchor.ok_or(Error::Input("missing expected anchor"))?;
            let anchor = NoteTreeAnchor::new(
                context.expected().network_id(),
                NoteCount::new(count).map_err(|error| Error::Operation(error.to_string()))?,
                NoteRoot::from_bytes(root),
            );
            let decode_us = start.elapsed().as_micros();
            let start = Instant::now();
            let _evidence = verify_payment(runtime, &body, &anchor, &self.proof, &context)
                .map_err(|error| Error::Operation(error.to_string()))?;

            (decode_us, start.elapsed().as_micros())
        } else {
            let body = RewardWithdrawalBody::from_bytes(&self.body, context.body_limits())
                .map_err(|error| Error::Operation(error.to_string()))?;
            let decode_us = start.elapsed().as_micros();
            let start = Instant::now();
            let _evidence = verify_reward_withdrawal(runtime, &body, &self.proof, &context)
                .map_err(|error| Error::Operation(error.to_string()))?;

            (decode_us, start.elapsed().as_micros())
        };

        Ok(Sample {
            workload: self.workload,
            fixture_us: None,
            prove_api_us: None,
            body_encode_us: None,
            decode_us,
            verify_api_us,
            body_bytes: self.body.len(),
            proof_bytes: self.proof.byte_len(),
        })
    }

    /// Writes only public interoperability data into a previously nonexistent directory.
    ///
    /// # Errors
    ///
    /// Fails rather than replacing an existing run or silently losing a partial write.
    pub fn write(&self, directory: &Path) -> Result<(), Error> {
        fs::create_dir(directory)?;
        let mut files = vec![
            ("body.bin", self.body.as_slice()),
            ("proof.bin", self.proof.as_bytes()),
        ];
        let count;
        if let Some((root, value)) = &self.anchor {
            count = value.to_le_bytes();
            files.push(("anchor-root.bin", root));
            files.push(("anchor-count.bin", &count));
        }

        for (name, bytes) in files {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join(name))?
                .write_all(bytes)?;
        }

        Ok(())
    }
}

/// Reads at most the selected ceiling and one excess byte before rejecting oversized input.
fn read_bounded(reader: impl Read, maximum: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(Error::Input("public artifact exceeds its fixed size limit"));
    }

    Ok(bytes)
}

/// Exact structural limits at the external file boundary.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The inclusive bound accepts exactly sized data and rejects its next byte.
    #[test]
    fn public_input_limit_is_inclusive_and_stops_at_one_excess_byte() {
        assert_eq!(read_bounded(Cursor::new([1; 64]), 64).unwrap().len(), 64);
        let mut reader = Cursor::new([1; 1024]);
        assert!(matches!(
            read_bounded(&mut reader, 64),
            Err(Error::Input(_))
        ));
        assert_eq!(reader.position(), 65);
    }
}
