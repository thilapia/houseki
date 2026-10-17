//! Canonical native withdrawal body lengths, encoding and decoding.

use super::{BodyCodecError, BodyCodecLimits, bound_body, reader, reserve, writer};
use crate::{EncodedMlDsa87PublicKey, RewardAccountId, RewardWithdrawalBody, WithdrawalNonce};

impl RewardWithdrawalBody {
    /// Returns the checked complete V1 length under the supplied active byte limits.
    ///
    /// # Errors
    ///
    /// Checks the sole payload and wire length before arithmetic and the complete body bound.
    pub fn encoded_len(&self, limits: BodyCodecLimits) -> Result<usize, BodyCodecError> {
        let length = 2796_usize
            .checked_add(writer::output_len(self.output(), limits)?)
            .ok_or(BodyCodecError::LengthOverflow)?;

        bound_body(length, limits)
    }

    /// Encodes the complete V1 withdrawal including its full envelope and separate public fee.
    ///
    /// Proof and signature bytes are excluded, with no account authority or crypto validation.
    ///
    /// # Errors
    ///
    /// Rechecks byte bounds before allocating and returns no bytes on reservation failure.
    pub fn to_bytes(&self, limits: BodyCodecLimits) -> Result<Vec<u8>, BodyCodecError> {
        let mut bytes = reserve(self.encoded_len(limits)?)?;

        writer::header(&mut bytes, 2, self.context());
        bytes.extend_from_slice(self.reward_account_id().as_bytes());
        bytes.extend_from_slice(self.withdrawal_public_key().as_bytes());
        bytes.extend_from_slice(&self.nonce().value().to_le_bytes());
        bytes.extend_from_slice(&self.public_amount().atoms().to_le_bytes());
        bytes.extend_from_slice(&self.public_fee().atoms().to_le_bytes());
        writer::output(&mut bytes, self.output())?;

        Ok(bytes)
    }

    /// Decodes exactly one V1 withdrawal with a positive public amount and bounded fee.
    ///
    /// Envelope bytes remain opaque, without a signature, account authority or proof claim.
    ///
    /// # Errors
    ///
    /// Checks total bytes before full headers and payload lengths before allocation.
    ///
    /// Rejects invalid amounts or validity bounds, a zero withdrawal and trailing bytes.
    pub fn from_bytes(bytes: &[u8], limits: BodyCodecLimits) -> Result<Self, BodyCodecError> {
        let mut reader = reader::Reader::new(bytes, 2, limits)?;
        let context = reader.context()?;
        let account = RewardAccountId::from_bytes(reader.array()?);
        let authority = EncodedMlDsa87PublicKey::from_bytes(reader.array()?);
        let nonce = WithdrawalNonce::new(u64::from_le_bytes(reader.array()?));
        let amount = reader.amount()?;
        let fee = reader.amount()?;
        let output = reader.output(limits)?;

        reader.finish()?;

        Ok(Self::new(
            context, account, authority, nonce, amount, fee, output,
        )?)
    }
}
