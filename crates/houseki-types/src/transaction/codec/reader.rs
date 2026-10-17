//! Checked borrowed parsing before count and payload allocations.

use super::{BodyCodecError, BodyCodecLimits, reserve};
use crate::{
    Amount, CheckpointSequence, EncodedMlKem1024Ciphertext, EncryptedNoteEnvelope, FeeScheduleId,
    NetworkId, NoteCommitment, NoteOutput, PaymentShape, ProofProfileId, ProtocolVersion,
    TransactionContext, ValidityCheckpointRange,
};

/// A bounded cursor borrowing the unconsumed canonical input.
pub(super) struct Reader<'a> {
    /// Remaining bytes, shortened only after a checked field read.
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Checks the complete input bound, full codec version and expected operation tag.
    pub(super) fn new(
        bytes: &'a [u8],
        kind: u32,
        limits: BodyCodecLimits,
    ) -> Result<Self, BodyCodecError> {
        super::bound_body(bytes.len(), limits)?;
        let mut reader = Self { bytes };
        let version = u32::from_le_bytes(reader.array()?);
        if version != 1 {
            return Err(BodyCodecError::UnsupportedVersion { version });
        }
        let actual = u32::from_le_bytes(reader.array()?);
        if actual != kind {
            return Err(BodyCodecError::UnexpectedKind {
                actual,
                expected: kind,
            });
        }
        Ok(reader)
    }

    /// Borrows a complete field only after checking available bytes.
    fn take(&mut self, length: usize) -> Result<&'a [u8], BodyCodecError> {
        let field = self.bytes.get(..length).ok_or(BodyCodecError::Truncated)?;
        self.bytes = &self.bytes[length..];
        Ok(field)
    }

    /// Copies a fixed public field after checking that its complete encoding exists.
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], BodyCodecError> {
        Ok(self
            .take(N)?
            .try_into()
            .expect("checked fixed field length"))
    }

    /// Parses the complete common context with the existing validity range invariant.
    pub(super) fn context(&mut self) -> Result<TransactionContext, BodyCodecError> {
        let network = NetworkId::from_bytes(self.array()?);
        let protocol = ProtocolVersion::new(u32::from_le_bytes(self.array()?));
        let proof = ProofProfileId::new(u32::from_le_bytes(self.array()?));
        let schedule = FeeScheduleId::new(u32::from_le_bytes(self.array()?));
        let start = CheckpointSequence::new(u64::from_le_bytes(self.array()?));
        let end = CheckpointSequence::new(u64::from_le_bytes(self.array()?));
        Ok(TransactionContext::new(
            network,
            protocol,
            proof,
            schedule,
            ValidityCheckpointRange::new(start, end)?,
        ))
    }

    /// Parses a bounded atom count without treating a fee as an ordinary note.
    pub(super) fn amount(&mut self) -> Result<Amount, BodyCodecError> {
        Ok(Amount::from_atoms(u128::from_le_bytes(self.array()?))?)
    }

    /// Converts a complete wire count and enforces the corresponding nonempty active bound.
    pub(super) fn count(
        &mut self,
        inputs: bool,
        limits: BodyCodecLimits,
    ) -> Result<usize, BodyCodecError> {
        let count = usize::try_from(u64::from_le_bytes(self.array()?))
            .map_err(|_| BodyCodecError::LengthOverflow)?;
        let shape = if inputs {
            PaymentShape::new(count, 1)?
        } else {
            PaymentShape::new(1, count)?
        };
        limits.payment_counts().validate_shape(shape)?;
        Ok(count)
    }

    /// Checks the minimum bytes for a declared list and required following fields before allocation.
    pub(super) fn require_list(
        &self,
        count: usize,
        item_bytes: usize,
        following: usize,
    ) -> Result<(), BodyCodecError> {
        let needed = count
            .checked_mul(item_bytes)
            .and_then(|n| n.checked_add(following))
            .ok_or(BodyCodecError::LengthOverflow)?;
        if needed > self.bytes.len() {
            return Err(BodyCodecError::Truncated);
        }
        Ok(())
    }

    /// Parses a full opaque envelope after checking its payload bound and available input.
    pub(super) fn output(&mut self, limits: BodyCodecLimits) -> Result<NoteOutput, BodyCodecError> {
        let commitment = NoteCommitment::from_bytes(self.array()?);
        let encapsulation = EncodedMlKem1024Ciphertext::from_bytes(self.array()?);
        let length = usize::try_from(u64::from_le_bytes(self.array()?))
            .map_err(|_| BodyCodecError::LengthOverflow)?;
        super::bound_payload(length, limits)?;
        let bytes = self.take(length)?;
        let mut payload = reserve(length)?;
        payload.extend_from_slice(bytes);
        let envelope =
            EncryptedNoteEnvelope::new(encapsulation, payload, limits.max_payload_bytes())
                .expect("payload length checked before allocation");
        Ok(NoteOutput::new(commitment, envelope))
    }

    /// Rejects every suffix after the complete typed body.
    pub(super) fn finish(self) -> Result<(), BodyCodecError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(BodyCodecError::TrailingBytes)
        }
    }
}
