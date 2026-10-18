//! Public conformance artifacts covering both families and every payment shape.

use crate::body::Body;
use houseki_proofs::{
    EXPERIMENTAL_PAYMENT_PROFILE, EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE, ProofContext,
};
use houseki_types::{
    BodyCodecLimits, EncodedTransactionProof, NoteCount, NoteRoot, NoteTreeAnchor, PaymentBody,
    PaymentCountLimits, RewardWithdrawalBody,
};
use std::{error::Error, fs::File, io::Read, path::Path};

/// Immutable expected statement and valid canonical proof for one corpus entry.
pub(crate) struct Seed {
    /// Stable public fixture identifier.
    pub(crate) name: String,

    /// Original body and independent anchor when applicable.
    pub(crate) body: Body,

    /// Canonical original body bytes for statement mutations.
    pub(crate) bytes: Vec<u8>,

    /// Original valid proof, never selected by mutated metadata.
    pub(crate) proof: EncodedTransactionProof,

    /// Expected profile and protocol context resolved from the trusted fixture.
    pub(crate) context: ProofContext,
}

impl Seed {
    /// Loads the complete finite corpus under fixed file-size ceilings.
    pub(crate) fn load_all(directory: &Path) -> Result<Vec<Self>, Box<dyn Error>> {
        let mut seeds = Vec::new();
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                seeds.push(Self::load(
                    directory,
                    &format!("payment-{inputs}-{outputs}"),
                    Some((inputs, outputs)),
                )?);
            }
        }

        seeds.push(Self::load(directory, "withdrawal", None)?);

        Ok(seeds)
    }

    /// Decodes a bounded original artifact without importing any protected witness owner.
    fn load(
        directory: &Path,
        name: &str,
        shape: Option<(usize, usize)>,
    ) -> Result<Self, Box<dyn Error>> {
        let directory = directory.join(name);
        let limits = BodyCodecLimits::new(PaymentCountLimits::new(4, 2)?, 4096, 16384);
        let bytes = read(&directory.join("body.bin"), 16384)?;
        let body = if let Some((inputs, outputs)) = shape {
            let body = PaymentBody::from_bytes(&bytes, limits)?;
            assert_eq!(body.inputs().input_count(), inputs);
            assert_eq!(body.outputs().output_count(), outputs);
            assert_eq!(
                body.context().proof_profile_id(),
                EXPERIMENTAL_PAYMENT_PROFILE
            );
            let count = read(&directory.join("anchor-count.bin"), 16)?;
            let count = NoteCount::new(u128::from_le_bytes(
                count.try_into().map_err(|_| "invalid expected count")?,
            ))?;
            let anchor = NoteTreeAnchor::new(
                body.context().network_id(),
                count,
                NoteRoot::from_bytes(
                    read(&directory.join("anchor-root.bin"), 64)?
                        .try_into()
                        .map_err(|_| "invalid expected root")?,
                ),
            );

            Body::Payment {
                body: Box::new(body),
                anchor,
            }
        } else {
            let body = RewardWithdrawalBody::from_bytes(&bytes, limits)?;
            assert_eq!(
                body.context().proof_profile_id(),
                EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE
            );

            Body::Withdrawal(Box::new(body))
        };

        let context = ProofContext::new(body.context())?;
        let proof = EncodedTransactionProof::new(
            read(&directory.join("proof.bin"), context.max_proof_bytes())?,
            context.max_proof_bytes(),
        )?;

        Ok(Self {
            name: name.to_owned(),
            body,
            bytes,
            proof,
            context,
        })
    }
}

/// Rejects oversized public fixture files before they can expand corpus memory.
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("fixture exceeds its byte bound".into());
    }

    Ok(bytes)
}
