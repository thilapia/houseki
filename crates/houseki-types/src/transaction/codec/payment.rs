//! Canonical native payment body lengths, encoding and decoding.

use super::{BodyCodecError, BodyCodecLimits, bound_body, reader, reserve, writer};
use crate::{NoteRoot, Nullifier, PaymentBody, PaymentInputs, PaymentOutputs};

impl PaymentBody {
    /// Returns the checked complete V1 length under the supplied active limits.
    ///
    /// # Errors
    ///
    /// Checks actual counts, each payload and wire lengths before the complete body bound.
    pub fn encoded_len(&self, limits: BodyCodecLimits) -> Result<usize, BodyCodecError> {
        limits.payment_counts().validate_shape(self.shape())?;
        u64::try_from(self.inputs().input_count()).map_err(|_| BodyCodecError::LengthOverflow)?;
        u64::try_from(self.outputs().output_count()).map_err(|_| BodyCodecError::LengthOverflow)?;

        let mut length = self
            .inputs()
            .input_count()
            .checked_mul(64)
            .and_then(|n| n.checked_add(196))
            .ok_or(BodyCodecError::LengthOverflow)?;
        for output in self.outputs().outputs() {
            length = length
                .checked_add(writer::output_len(output, limits)?)
                .ok_or(BodyCodecError::LengthOverflow)?;
        }

        bound_body(length, limits)
    }

    /// Encodes all ordered effects and full opaque envelopes, excluding proof bytes.
    ///
    /// Encoding preserves repeated outputs without authenticating encryption or protocol validity.
    ///
    /// # Errors
    ///
    /// Rechecks active bounds before allocating and returns no bytes on reservation failure.
    pub fn to_bytes(&self, limits: BodyCodecLimits) -> Result<Vec<u8>, BodyCodecError> {
        let mut bytes = reserve(self.encoded_len(limits)?)?;

        writer::header(&mut bytes, 1, self.context());
        bytes.extend_from_slice(self.inputs().anchor().as_bytes());
        bytes.extend_from_slice(
            &u64::try_from(self.inputs().input_count())
                .map_err(|_| BodyCodecError::LengthOverflow)?
                .to_le_bytes(),
        );
        for nullifier in self.inputs().nullifiers() {
            bytes.extend_from_slice(nullifier.as_bytes());
        }

        bytes.extend_from_slice(&self.public_fee().atoms().to_le_bytes());
        bytes.extend_from_slice(
            &u64::try_from(self.outputs().output_count())
                .map_err(|_| BodyCodecError::LengthOverflow)?
                .to_le_bytes(),
        );
        for output in self.outputs().outputs() {
            writer::output(&mut bytes, output)?;
        }

        Ok(bytes)
    }

    /// Decodes exactly one V1 payment with bounded opaque envelopes and checked list invariants.
    ///
    /// Every declared count is checked against its active maximum and available minimum bytes
    /// before list allocation, while payload bytes remain uninterpreted.
    ///
    /// # Errors
    ///
    /// Checks total bytes before full headers, then field constraints in canonical order.
    ///
    /// Rejects empty lists, repeated nullifiers, invalid amounts or validity and trailing bytes.
    pub fn from_bytes(bytes: &[u8], limits: BodyCodecLimits) -> Result<Self, BodyCodecError> {
        let mut reader = reader::Reader::new(bytes, 1, limits)?;
        let context = reader.context()?;
        let anchor = NoteRoot::from_bytes(reader.array()?);

        let count = reader.count(true, limits)?;
        reader.require_list(count, 64, 24 + 1640)?;

        let mut nullifiers = reserve(count)?;
        for _ in 0..count {
            nullifiers.push(Nullifier::from_bytes(reader.array()?));
        }

        let inputs = PaymentInputs::new(anchor, nullifiers, limits.payment_counts())?;

        let fee = reader.amount()?;
        let count = reader.count(false, limits)?;
        reader.require_list(count, 1640, 0)?;

        let mut outputs = reserve(count)?;
        for _ in 0..count {
            outputs.push(reader.output(limits)?);
        }

        reader.finish()?;

        Ok(Self::new(
            context,
            inputs,
            PaymentOutputs::new(outputs, limits.payment_counts())?,
            fee,
            limits.payment_counts(),
        )?)
    }
}
